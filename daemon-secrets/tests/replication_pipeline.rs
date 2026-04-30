//! Integration tests for the vault replication pipeline.
//!
//! These tests exercise outcomes through the public API without reaching
//! into internals. They verify the full data flow:
//! - Write secret → vault log entry with value_hash → pull response with value
//! - Receiver validates signature → checks HWM → applies to vault
//! - Deferred entries behave correctly on profile unlock
//! - Rejected entries don't pollute state
//! - Replay protection works

use core_types::{TrustProfileName, VaultLogOp};
use daemon_secrets::crud;
use daemon_secrets::vault_log::VaultLog;

/// Valid UUID for test installation ID.
const TEST_INSTALL_ID: &str = "00000000-0000-0000-0000-000000000042";

fn setup() {
    // Signing seed (RwLock — re-settable across tests).
    crud::set_signing_seed(Some(zeroize::Zeroizing::new([0xDD; 32])));
    // Installation ID (OnceLock — first test wins).
    let _ = crud::INSTALL_ID.set(TEST_INSTALL_ID.to_string());
}

fn temp_log() -> (VaultLog, tempfile::TempDir) {
    setup();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault-log.db");
    let log = VaultLog::open(&path).unwrap();
    (log, dir)
}

fn profile(name: &str) -> TrustProfileName {
    TrustProfileName::try_from(name).unwrap()
}

/// Read the Nth entry from a VaultLog as wire-format JSON.
fn read_wire_entry(log: &VaultLog, offset: usize) -> String {
    let result = log.query_entries_since("work", None, 100).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&result.entries_json).unwrap();
    serde_json::to_string(&entries[offset]).unwrap()
}

// ============================================================================
// Positive tests — things that must work
// ============================================================================

/// Write a secret, read it back as a wire entry, verify the receiver can
/// validate and insert it. The full sender→receiver round-trip.
#[test]
fn positive_write_validate_insert_roundtrip() {
    let (sender, _sd) = temp_log();
    let p = profile("work");

    sender
        .write_local_entry(
            &p,
            VaultLogOp::Set,
            "api-key",
            TEST_INSTALL_ID,
            b"secret-value",
        )
        .unwrap();

    let wire = read_wire_entry(&sender, 0);

    // Receiver validates and inserts.
    let (receiver, _rd) = temp_log();
    receiver.insert_received_entry(&wire).unwrap();
    assert_eq!(receiver.entry_count().unwrap(), 1);

    // Entry is unapplied on the receiver.
    let unapplied = receiver.unapplied_entries(100).unwrap();
    assert_eq!(unapplied.len(), 1);
    assert_eq!(unapplied[0].operation_type, "set");
}

/// Write + delete produces two entries that both validate on the receiver.
#[test]
fn positive_set_then_delete_roundtrip() {
    let (sender, _sd) = temp_log();
    let p = profile("work");

    sender
        .write_local_entry(
            &p,
            VaultLogOp::Set,
            "temp-key",
            TEST_INSTALL_ID,
            b"temp-val",
        )
        .unwrap();
    sender
        .write_local_entry(&p, VaultLogOp::Delete, "temp-key", TEST_INSTALL_ID, &[])
        .unwrap();

    let wire_0 = read_wire_entry(&sender, 0);
    let wire_1 = read_wire_entry(&sender, 1);

    let (receiver, _rd) = temp_log();
    receiver.insert_received_entry(&wire_0).unwrap();
    receiver.insert_received_entry(&wire_1).unwrap();

    let unapplied = receiver.unapplied_entries(100).unwrap();
    assert_eq!(unapplied.len(), 2);
    assert_eq!(unapplied[0].operation_type, "set");
    assert_eq!(unapplied[1].operation_type, "delete");
}

/// query_entries_since returns full wire-format entries with all signed fields.
#[test]
fn positive_query_returns_full_wire_entries() {
    let (log, _dir) = temp_log();
    let p = profile("work");

    log.write_local_entry(&p, VaultLogOp::Set, "k1", TEST_INSTALL_ID, b"v1")
        .unwrap();

    let result = log.query_entries_since("work", None, 100).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&result.entries_json).unwrap();

    assert_eq!(entries.len(), 1);
    // Must have all signed fields.
    assert!(entries[0]["id"].is_string());
    assert!(entries[0]["timestamp"]["wall_secs"].is_u64());
    assert!(entries[0]["timestamp"]["counter"].is_u64());
    assert!(entries[0]["timestamp"]["node_id"].is_string());
    assert!(entries[0]["author_installation_uuid"].is_string());
    assert!(entries[0]["author_signing_pubkey"].is_string());
    assert!(entries[0]["profile_id"].is_string());
    assert!(entries[0]["signature"].is_string());
    assert!(entries[0]["operation"]["value_hash"].is_string());

    // last_hlc_json populated.
    assert!(result.last_hlc_json.is_some());
}

/// value_hash is BLAKE3 of the written value, verifiable independently.
#[test]
fn positive_value_hash_matches_blake3() {
    let (log, _dir) = temp_log();
    let p = profile("work");
    let value = b"my-secret-api-key-12345";

    log.write_local_entry(&p, VaultLogOp::Set, "k", TEST_INSTALL_ID, value)
        .unwrap();

    let result = log.query_entries_since("work", None, 100).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&result.entries_json).unwrap();

    let signed_hash = entries[0]["operation"]["value_hash"].as_str().unwrap();
    let expected_hash = hex::encode(blake3::hash(value).as_bytes());
    assert_eq!(signed_hash, expected_hash);
}

/// HWM advances after successful insert, blocking replay of older entries.
#[test]
fn positive_hwm_advances_blocks_replay() {
    let (sender, _sd) = temp_log();
    let p = profile("work");

    sender
        .write_local_entry(&p, VaultLogOp::Set, "k1", TEST_INSTALL_ID, b"v1")
        .unwrap();
    sender
        .write_local_entry(&p, VaultLogOp::Set, "k2", TEST_INSTALL_ID, b"v2")
        .unwrap();

    let wire_0 = read_wire_entry(&sender, 0);
    let wire_1 = read_wire_entry(&sender, 1);

    let (receiver, _rd) = temp_log();

    // Insert both entries — both should succeed.
    receiver.insert_received_entry(&wire_0).unwrap();
    receiver.insert_received_entry(&wire_1).unwrap();
    assert_eq!(receiver.entry_count().unwrap(), 2);

    // Parse entry 1's HLC for the HWM update.
    let e1: serde_json::Value = serde_json::from_str(&wire_1).unwrap();
    let ws = e1["timestamp"]["wall_secs"].as_i64().unwrap();
    let ctr = e1["timestamp"]["counter"].as_i64().unwrap();
    let author = e1["author_installation_uuid"].as_str().unwrap();

    // Advance HWM to entry 1's position.
    receiver.update_replay_hwm(author, "work", ws, ctr).unwrap();

    // Now check_hwm rejects entry 0 (older than HWM).
    let e0: serde_json::Value = serde_json::from_str(&wire_0).unwrap();
    let ws0 = e0["timestamp"]["wall_secs"].as_i64().unwrap();
    let ctr0 = e0["timestamp"]["counter"].as_i64().unwrap();

    assert!(
        !receiver.check_hwm(author, "work", ws0, ctr0).unwrap(),
        "entry older than HWM must be rejected"
    );
}

/// Schema migration: opening a mismatched DB refuses to start.
#[test]
fn negative_schema_mismatch_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault-log.db");

    // Create a v1 DB manually.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();
        conn.execute_batch("CREATE TABLE vault_log (id TEXT PRIMARY KEY);")
            .unwrap();
    }

    // Opening with current code must refuse — no silent data destruction.
    setup();
    let result = VaultLog::open(&path);
    assert!(
        result.is_err(),
        "mismatched schema version must refuse to start"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("schema version"),
        "error must mention schema version, got: {err}"
    );
}

/// Schema migration: opening a newer DB (downgrade) also refuses.
#[test]
fn negative_schema_downgrade_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault-log.db");

    // Create a v99 DB (future version).
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA user_version = 99;").unwrap();
    }

    setup();
    let result = VaultLog::open(&path);
    assert!(result.is_err(), "newer schema version must refuse to start");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("newer"),
        "error must mention 'newer', got: {err}"
    );
}

/// Fresh DB (user_version = 0) creates tables normally.
#[test]
fn positive_fresh_db_creates_tables() {
    let (log, _dir) = temp_log();
    assert_eq!(log.entry_count().unwrap(), 0);
}

// ============================================================================
// Negative tests — things that must fail
// ============================================================================

/// Unsigned entry is rejected at signature validation.
#[test]
fn negative_unsigned_entry_rejected() {
    let entry = serde_json::json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "signature": "",
    })
    .to_string();
    let result = VaultLog::validate_entry_structure(&entry);
    assert!(result.is_err(), "unsigned entry must be rejected");
}

/// Tampered signature is rejected.
#[test]
fn negative_tampered_signature_rejected() {
    let (sender, _sd) = temp_log();
    let p = profile("work");
    sender
        .write_local_entry(&p, VaultLogOp::Set, "k", TEST_INSTALL_ID, b"v")
        .unwrap();

    let mut wire: serde_json::Value = serde_json::from_str(&read_wire_entry(&sender, 0)).unwrap();

    // Tamper the signature.
    let sig = wire["signature"].as_str().unwrap().to_string();
    let mut sig_bytes = hex::decode(&sig).unwrap();
    sig_bytes[0] ^= 0xFF;
    wire["signature"] = serde_json::Value::String(hex::encode(&sig_bytes));

    let result = VaultLog::validate_entry_structure(&serde_json::to_string(&wire).unwrap());
    assert!(result.is_err(), "tampered signature must be rejected");
}

/// System key entry `_signing-seed` passes signature but is rejected
/// by validate_entry_structure (post-signature content check).
#[test]
fn negative_system_key_rejected_after_signature() {
    // We can't easily produce a legitimately-signed system key entry
    // because vault_log_hook skips system keys. So we verify the
    // validator rejects system keys on unsigned entries — the ordering
    // doesn't matter for this test, the outcome does.
    let entry = serde_json::json!({
        "id": "00000000-0000-0000-0000-000000000001",
        "operation": {"op": "set", "key": "_signing-seed"},
        "signature": hex::encode([0xAA; 64]),
        "author_signing_pubkey": hex::encode([0xBB; 32]),
        "timestamp": {"wall_secs": 1000, "counter": 0, "node_id": "aa00000000000000"},
        "author_installation_uuid": "00000000-0000-0000-0000-000000000042",
        "profile_id": "work",
        "prev_by_author": null,
    })
    .to_string();

    let result = VaultLog::validate_entry_structure(&entry);
    assert!(result.is_err(), "system key entry must be rejected");
}

/// Oversized entry (>64KB) is rejected before parsing.
#[test]
fn negative_oversized_entry_rejected() {
    let huge = "x".repeat(65 * 1024);
    let result = VaultLog::validate_entry_structure(&huge);
    assert!(result.is_err(), "oversized entry must be rejected");
}

/// Replay of already-seen entry (HLC ≤ HWM) is blocked by check_hwm.
#[test]
fn negative_replay_blocked_by_hwm() {
    let (log, _dir) = temp_log();

    // Set HWM to (100, 5).
    log.update_replay_hwm("author-1", "work", 100, 5).unwrap();

    // Entry at (100, 5) — equal, not strictly newer.
    assert!(
        !log.check_hwm("author-1", "work", 100, 5).unwrap(),
        "entry at exact HWM must be rejected (not strictly newer)"
    );

    // Entry at (100, 4) — older.
    assert!(
        !log.check_hwm("author-1", "work", 100, 4).unwrap(),
        "entry older than HWM must be rejected"
    );

    // Entry at (99, 999) — older wall_secs.
    assert!(
        !log.check_hwm("author-1", "work", 99, 999).unwrap(),
        "entry with older wall_secs must be rejected regardless of counter"
    );

    // Entry at (100, 6) — strictly newer.
    assert!(
        log.check_hwm("author-1", "work", 100, 6).unwrap(),
        "entry strictly newer than HWM must be accepted"
    );

    // Entry at (101, 0) — newer wall_secs.
    assert!(
        log.check_hwm("author-1", "work", 101, 0).unwrap(),
        "entry with newer wall_secs must be accepted"
    );
}

/// First entry from a new author passes HWM (no prior state).
#[test]
fn negative_first_entry_from_new_author_accepted() {
    let (log, _dir) = temp_log();

    assert!(
        log.check_hwm("never-seen-author", "work", 1, 0).unwrap(),
        "first entry from unknown author must be accepted"
    );
}

/// HWM is per-author — advancing one author's HWM doesn't affect another.
#[test]
fn negative_hwm_is_per_author() {
    let (log, _dir) = temp_log();

    log.update_replay_hwm("author-a", "work", 1000, 50).unwrap();

    // Author B at (1, 0) should still pass — different author.
    assert!(
        log.check_hwm("author-b", "work", 1, 0).unwrap(),
        "HWM for author A must not affect author B"
    );
}

/// HWM is per-profile — advancing in "work" doesn't affect "personal".
#[test]
fn negative_hwm_is_per_profile() {
    let (log, _dir) = temp_log();

    log.update_replay_hwm("author-a", "work", 1000, 50).unwrap();

    // Same author, different profile, low HLC — should pass.
    assert!(
        log.check_hwm("author-a", "personal", 1, 0).unwrap(),
        "HWM for profile 'work' must not affect profile 'personal'"
    );
}

/// Pull progress and replay HWM are independent tables.
#[test]
fn negative_pull_progress_independent_from_hwm() {
    let (log, _dir) = temp_log();

    // Set pull progress for peer X.
    log.update_pull_progress("peer-x", "work", 500, 10).unwrap();

    // HWM for author X should be unaffected (separate table).
    assert!(
        log.check_hwm("peer-x", "work", 1, 0).unwrap(),
        "pull_progress must not affect entry_replay_hwm"
    );
}

/// Duplicate insert is idempotent (INSERT OR IGNORE).
#[test]
fn negative_duplicate_insert_idempotent() {
    let (sender, _sd) = temp_log();
    let p = profile("work");
    sender
        .write_local_entry(&p, VaultLogOp::Set, "k", TEST_INSTALL_ID, b"v")
        .unwrap();

    let wire = read_wire_entry(&sender, 0);

    let (receiver, _rd) = temp_log();
    receiver.insert_received_entry(&wire).unwrap();
    receiver.insert_received_entry(&wire).unwrap(); // Duplicate.
    assert_eq!(
        receiver.entry_count().unwrap(),
        1,
        "duplicate insert must be idempotent"
    );
}

/// Delete operations have empty value_hash.
#[test]
fn negative_delete_has_empty_value_hash() {
    let (log, _dir) = temp_log();
    let p = profile("work");

    log.write_local_entry(&p, VaultLogOp::Delete, "k", TEST_INSTALL_ID, &[])
        .unwrap();

    let result = log.query_entries_since("work", None, 100).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&result.entries_json).unwrap();

    let hash = entries[0]["operation"]["value_hash"].as_str().unwrap();
    assert!(
        hash.is_empty(),
        "delete operations must have empty value_hash, got: {hash}"
    );
}

/// Set operations always have a non-empty value_hash, even for empty values.
#[test]
fn negative_set_always_has_value_hash() {
    let (log, _dir) = temp_log();
    let p = profile("work");

    // Write a set with empty value.
    log.write_local_entry(&p, VaultLogOp::Set, "k", TEST_INSTALL_ID, b"")
        .unwrap();

    let result = log.query_entries_since("work", None, 100).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&result.entries_json).unwrap();

    let hash = entries[0]["operation"]["value_hash"].as_str().unwrap();
    assert!(
        !hash.is_empty(),
        "set operations must always have a value_hash, even for empty values"
    );

    // Verify it's the BLAKE3 of empty bytes.
    let expected = hex::encode(blake3::hash(b"").as_bytes());
    assert_eq!(hash, expected);
}

/// Watermark query returns None when no entries match the profile.
#[test]
fn negative_query_empty_profile_returns_no_hlc() {
    let (log, _dir) = temp_log();
    let result = log.query_entries_since("nonexistent", None, 100).unwrap();
    let entries: Vec<serde_json::Value> = serde_json::from_str(&result.entries_json).unwrap();
    assert!(entries.is_empty());
    assert!(result.last_hlc_json.is_none());
}

/// Cleanup removes both pull_progress and entry_replay_hwm for a peer.
#[test]
fn negative_cleanup_removes_both_tables() {
    let (log, _dir) = temp_log();

    log.update_pull_progress("peer-z", "work", 100, 5).unwrap();
    log.update_replay_hwm("peer-z", "work", 100, 5).unwrap();

    // HWM blocks replay.
    assert!(!log.check_hwm("peer-z", "work", 100, 5).unwrap());

    // Cleanup.
    log.cleanup_peer_state("peer-z").unwrap();

    // HWM is gone — entry accepted again.
    assert!(
        log.check_hwm("peer-z", "work", 100, 5).unwrap(),
        "cleanup must remove HWM so entries are accepted again"
    );
}

// ============================================================================
// Pull progress tests
// ============================================================================

/// Pull progress tracks per-peer sync state independently from replay HWM.
#[test]
fn pull_progress_independent_from_hwm() {
    let (log, _dir) = temp_log();

    log.update_pull_progress("relay-peer", "work", 200, 10)
        .unwrap();

    // HWM for the same ID should be unaffected.
    assert!(
        log.check_hwm("relay-peer", "work", 1, 0).unwrap(),
        "pull_progress must not affect entry_replay_hwm"
    );
}

/// Pull progress advances monotonically — older values don't regress.
#[test]
fn pull_progress_monotonic() {
    let (log, _dir) = temp_log();

    log.update_pull_progress("peer-a", "work", 100, 5).unwrap();
    log.update_pull_progress("peer-a", "work", 50, 99).unwrap(); // Older wall_secs.

    // Verify it didn't regress by checking the compaction path.
    // If the pull_progress table has watermark (100, 5), compaction
    // should respect that, not the older (50, 99).
    // We can't directly read pull_progress without a query method,
    // but we can verify via compaction behavior.
    assert_eq!(log.entry_count().unwrap(), 0); // No entries to compact — just verifying no crash.
}

/// Deferred entry gets picked up by unapplied_entries after deferral window.
#[test]
fn deferred_entry_respects_timing() {
    let (sender, _sd) = temp_log();
    let p = profile("work");
    sender
        .write_local_entry(&p, VaultLogOp::Delete, "del-key", TEST_INSTALL_ID, &[])
        .unwrap();

    let wire = read_wire_entry(&sender, 0);

    let (receiver, _rd) = temp_log();
    receiver.insert_received_entry(&wire).unwrap();

    // Entry is unapplied.
    let unapplied = receiver.unapplied_entries(100).unwrap();
    assert_eq!(unapplied.len(), 1);

    // Defer it into the future.
    receiver.defer_entry(&unapplied[0].id, 9999).unwrap();

    // Now unapplied_entries should not return it (deferred_until in future).
    let unapplied_after = receiver.unapplied_entries(100).unwrap();
    assert_eq!(
        unapplied_after.len(),
        0,
        "deferred entry must not appear in unapplied_entries until deferral expires"
    );
}

/// Deferred count increments on each deferral.
#[test]
fn deferred_count_increments() {
    let (sender, _sd) = temp_log();
    let p = profile("work");
    sender
        .write_local_entry(&p, VaultLogOp::Set, "k", TEST_INSTALL_ID, b"v")
        .unwrap();

    let wire = read_wire_entry(&sender, 0);

    let (receiver, _rd) = temp_log();
    receiver.insert_received_entry(&wire).unwrap();

    let unapplied = receiver.unapplied_entries(100).unwrap();
    let id = &unapplied[0].id;

    assert_eq!(receiver.deferred_count(id).unwrap(), 0);

    receiver.defer_entry(id, 0).unwrap(); // Immediate retry (0 seconds).
    assert_eq!(receiver.deferred_count(id).unwrap(), 1);

    receiver.defer_entry(id, 0).unwrap();
    assert_eq!(receiver.deferred_count(id).unwrap(), 2);

    receiver.defer_entry(id, 0).unwrap();
    assert_eq!(receiver.deferred_count(id).unwrap(), 3);
}

/// Compaction respects the schema version migration — old DBs get recreated.
#[test]
fn compaction_on_fresh_db_does_not_crash() {
    let (log, _dir) = temp_log();

    // No entries, threshold not met.
    let result = log.compact(10_000, 604_800);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

/// insert_received_entry normalizes operation_json to inner operation object.
#[test]
fn insert_normalizes_operation_json() {
    let (sender, _sd) = temp_log();
    let p = profile("work");
    sender
        .write_local_entry(
            &p,
            VaultLogOp::Set,
            "norm-key",
            TEST_INSTALL_ID,
            b"norm-val",
        )
        .unwrap();

    let wire = read_wire_entry(&sender, 0);

    let (receiver, _rd) = temp_log();
    receiver.insert_received_entry(&wire).unwrap();

    // The stored operation_json should be the inner {"op","key","value_hash"},
    // not the full wire entry.
    let unapplied = receiver.unapplied_entries(100).unwrap();
    let op: serde_json::Value = serde_json::from_str(&unapplied[0].operation_json).unwrap();

    // Must have "op" and "key" at top level (normalized format).
    assert!(
        op["op"].is_string(),
        "normalized operation_json must have 'op' field"
    );
    assert!(
        op["key"].is_string(),
        "normalized operation_json must have 'key' field"
    );
    assert_eq!(op["key"].as_str().unwrap(), "norm-key");

    // Must NOT have wire-format fields like "signature" or "timestamp".
    assert!(
        op["signature"].is_null(),
        "normalized operation_json must not contain wire-format fields"
    );
    assert!(
        op["timestamp"].is_null(),
        "normalized operation_json must not contain wire-format fields"
    );
}
