# Crosscheck: Adversarial Security Review Validation

**Date**: 2026-02-26
**Reviewer**: Independent principal staff engineer crosscheck
**Scope**: All findings from AGENT_ANALYSIS.adversarial-security-review.md

## Finding-by-Finding Validation

### P0-001: `pragma_rekey_clear()` is synchronous but called in async context without blocking guard

**Cited location**: `core-secrets/src/sqlcipher.rs:173-192`, `daemon-secrets/src/main.rs:134,409,508`
**Verdict**: PARTIAL
**Actual code** (`core-secrets/src/sqlcipher.rs:173-192`):
```rust
pub fn pragma_rekey_clear(&self) {
    match self.conn.lock() {
        Ok(conn) => {
            if let Err(e) = conn.execute_batch("PRAGMA rekey = '';") {
                tracing::warn!(
                    path = %self.db_path.display(),
                    error = %e,
                    "PRAGMA rekey clear failed — C-level key buffer may not be zeroized"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                path = %self.db_path.display(),
                error = %e,
                "failed to acquire conn lock for PRAGMA rekey clear"
            );
        }
    }
}
```

**Analysis**: The reviewer correctly identifies that `std::sync::Mutex` is used (line 24: `conn: Mutex<Connection>`) and `pragma_rekey_clear()` is synchronous. The call sites in `daemon-secrets/src/main.rs` are verified:
- Line 134: `vault.store().pragma_rekey_clear();` in `deactivate_profile()`
- Lines 408-409: `vault.store().pragma_rekey_clear();` in shutdown drain loop
- Lines 507-508: `vault.store().pragma_rekey_clear();` in lock handler

The mutex poisoning concern is VALID. On line 184, a poisoned mutex causes a warning log and return without zeroizing. The `SecretsStore` trait methods (`get`, `set`, `delete`, `list_keys`) at lines 207, 238, 257, 278 all use `self.conn.lock().map_err(...)` which returns `Err` on poison, propagating up. A panic during `encrypt_value()` or `decrypt_value()` would poison the mutex.

However, the severity is overstated. The `#[tokio::main]` on daemon-secrets (line 262) defaults to current-thread runtime. A panic in any handler aborts the process entirely (tokio's default panic behavior on current-thread runtime is propagation to `main`), so the poisoned-mutex scenario requires a `catch_unwind` or `spawn` that catches the panic. Since `handle_message` is called directly in the select loop (not spawned), a panic there crashes daemon-secrets. The mutex never gets to the "poisoned but process alive" state under the current architecture.

The tokio worker thread blocking concern is also overstated: on a single-threaded runtime, there is no other worker thread to starve. The mutex is uncontended.

**Adjusted severity**: P2 (defense-in-depth gap, not exploitable under current runtime)
**Corrected remediation**: The `unwrap_or_else(|e| e.into_inner())` fix is still correct as defense-in-depth. It costs nothing and protects against future architectural changes (multi-threaded runtime, spawned tasks).

---

### P0-002: Confirmation channel shared across concurrent operations without serialization

**Cited location**: `daemon-profile/src/main.rs:197,304-311,611,638`
**Verdict**: PARTIAL — correctly self-revised during analysis
**Actual code** (`daemon-profile/src/main.rs:197`):
```rust
let (confirm_tx, mut confirm_rx) = mpsc::channel::<Vec<u8>>(16);
```

Reconciliation call (`daemon-profile/src/main.rs:304-311`):
```rust
if watchdog_tick_count.is_multiple_of(2) {
    reconcile_secrets_state(
        &bus,
        daemon_id,
        &mut locked,
        &mut active_profiles,
        &confirm_tx,
        &mut confirm_rx,
    ).await;
}
```

**Analysis**: The reviewer correctly self-corrects that Rust's borrow checker prevents true concurrency here. The `&mut confirm_rx` is exclusively borrowed by whichever select arm is running.

The stale message scenario is the real concern. Looking at `activation.rs:236`:
```rust
if response.correlation_id != Some(msg_id) {
    return Err(format!(
        "confirmation response correlation_id mismatch: expected {msg_id}, got {:?}",
        response.correlation_id
    ));
}
```

And `reconcile_secrets_state()` at `daemon-profile/src/main.rs:726-760` does NOT verify `correlation_id`. It simply calls `confirm_rx.recv()` and checks the payload type. However, the reviewer's analysis of the stale message scenario has a timing issue: the `ConfirmationGuard` is dropped when the `confirmed_rpc()` returns (via `_guard` at `activation.rs:222`). The guard's `Drop` deregisters the confirmation route from the bus server's routing table. So the window is:

1. `confirmed_rpc()` times out
2. Return from `confirmed_rpc()`, guard drops, deregisters route
3. Late response arrives at bus server -- route is already gone, response is NOT forwarded to `confirm_tx`

Actually, the `ConfirmationGuard::drop()` uses `try_write()` (server.rs:82). If it fails, it spawns a task. There is a race: the late response could arrive at `route_frame()` BEFORE the spawned cleanup task runs. In that case, the confirmation route still exists, and the response IS forwarded to `confirm_tx`. This is a real but extremely narrow window.

The `reconcile_secrets_state()` function at line 730 checks payload type:
```rust
if let EventKind::SecretsStateResponse { ... } = response.payload
```
A stale `ProfileActivateResponse` would NOT match this pattern and falls to the warning at line 757. So the reconciliation fails silently but is not corrupted.

**Adjusted severity**: P2 (silent reconciliation failure for one 30s cycle, not data corruption)
**Corrected remediation**: The reviewer's fix (drain `confirm_rx` with `try_recv()` before sending) is correct and simple. Additionally, `reconcile_secrets_state()` should verify `correlation_id` matches its own `msg_id` for defense-in-depth.

---

### P0-003: Deactivation failure path does not trigger reconciliation

**Cited location**: `daemon-profile/src/main.rs:648-655`
**Verdict**: VALID
**Actual code** (`daemon-profile/src/main.rs:648-655`):
```rust
Err(e) => {
    tracing::error!(
        profile = %profile_name,
        error = %e,
        "profile deactivation failed"
    );
    Some(EventKind::ProfileDeactivateResponse { success: false })
}
```

**Analysis**: Confirmed. There is no call to `reconcile_secrets_state()` in the deactivation error path. The `activation::deactivate()` at `activation.rs:168-176`:
```rust
Err(e) => {
    tracing::error!(
        error = %e,
        profile = %profile_name,
        "confirmed RPC timeout on ProfileDeactivate — reconciliation needed"
    );
    return Err(format!("confirmed RPC failed for ProfileDeactivate: {e}"));
}
```

The log message even says "reconciliation needed" but the caller doesn't perform it. The spec requirement for immediate reconciliation on deactivation timeout is unmet.

**Adjusted severity**: P1 (not P0 -- the 30s reconciliation watchdog provides eventual correction, and the state divergence is bounded)
**Corrected remediation**: Add `reconcile_secrets_state()` call before returning the error response. The reviewer's recommendation is correct.

---

### P1-001: `check_secret_requester()` is advisory-only with no enforcement

**Cited location**: `daemon-secrets/src/acl.rs:130-146`
**Verdict**: VALID
**Actual code** (`daemon-secrets/src/acl.rs:130-146`):
```rust
pub(crate) fn check_secret_requester(requester: DaemonId, verified_name: Option<&str>) {
    if let Some(name) = verified_name {
        match name {
            "daemon-secrets" | "daemon-launcher" => {} // Expected requesters.
            other => {
                tracing::warn!(
                    audit = "anomaly",
                    anomaly_type = "unexpected-secret-requester",
                    requester = %requester,
                    verified_name = other,
                    "daemon not expected to request secrets (verified identity)"
                );
            }
        }
    }
    // None = unregistered client (CLI relay via daemon-profile). Not anomalous.
}
```

**Analysis**: The function returns `()`. It is purely advisory. The reviewer correctly notes that a compromised daemon with no ACL restriction has unrestricted access to all secrets in all active profiles. The ACL system (`check_secret_access()`) is the real gate, but it defaults to allow-all when no ACL policy is configured.

However, the reviewer slightly overstates the impact. The bus server's clearance enforcement (server.rs:691-708) restricts what security level a daemon can emit at. Secret operations use `SecurityLevel::SecretsOnly`. Looking at daemon-secrets, it processes `SecretGet` from any sender. But the bus server routes the request to all subscribers, including daemon-secrets, regardless of the sender's clearance -- actually, looking at server.rs:785, the bus filters recipients by clearance (`conn.security_clearance < msg.security_level`), not senders. Wait, lines 691-708 DO check sender clearance: if `conn.security_clearance < msg.security_level`, the message is rejected. So a daemon with `Internal` clearance cannot emit a `SecretsOnly` message.

Looking at KNOWN_DAEMONS in daemon-profile/src/main.rs:30-37:
```rust
("daemon-secrets", SecurityLevel::SecretsOnly),
("daemon-wm", SecurityLevel::Internal),
("daemon-launcher", SecurityLevel::Internal),
```

A `daemon-wm` with `Internal` clearance trying to send `SecretGet` at `SecretsOnly` level would be rejected by the bus server. But wait -- does the CLI send `SecretGet` at `SecretsOnly`? Looking at open-sesame/src/main.rs:726:
```rust
match rpc(&client, event, SecurityLevel::SecretsOnly).await? {
```

The CLI uses an ephemeral keypair (unregistered), which gets `SecurityLevel::SecretsOnly` clearance (server.rs:528). So the CLI CAN send `SecretsOnly` messages. But what about a compromised `daemon-wm`? It has `Internal` clearance and cannot send `SecretsOnly` messages.

This means the clearance system already prevents `daemon-wm`/`daemon-clipboard` etc. from directly issuing secret requests. The `check_secret_requester()` advisory check is therefore defense-in-depth for a scenario that the clearance system already blocks.

**Adjusted severity**: P2 (the clearance system provides primary enforcement; the advisory check is defense-in-depth)
**Corrected remediation**: Document that clearance enforcement is the primary gate, not `check_secret_requester()`. Making it an enforcement point is still good defense-in-depth.

---

### P1-002: Rate limiter state not cleared on lock

**Cited location**: `daemon-secrets/src/main.rs:340`
**Verdict**: PARTIAL
**Actual code** (`daemon-secrets/src/main.rs:340`):
```rust
let mut rate_limiter = SecretRateLimiter::new();
```

Lock handler (`daemon-secrets/src/main.rs:504-518`):
```rust
EventKind::LockRequest => {
    if let Some(mut state) = ctx.unlocked_state.take() {
        state.active_profiles.clear();
        for (_profile, vault) in state.vaults.drain() {
            vault.store().pragma_rekey_clear();
            vault.flush().await;
            drop(vault);
        }
        drop(state);
        // ...
    }
    // No rate_limiter.clear() or reset
```

**Analysis**: The reviewer correctly identifies that the rate limiter is never cleared. The `HashMap<String, RateLimiter>` grows with each unique daemon name. However, the reviewer also correctly self-revises: governor's GCRA algorithm handles stale timestamps correctly (the bucket refills), so rate limiting still functions correctly after lock/unlock.

The memory growth concern is limited by the authenticated bus model: only daemons with valid Noise IK keys can connect, and there are a fixed set of KNOWN_DAEMONS (6 entries). CLI connections get the shared `__anonymous__` bucket. So the HashMap is bounded to ~7 entries in practice.

**Adjusted severity**: P3 (informational -- bounded memory growth, no functional impact)
**Corrected remediation**: Adding `rate_limiter = SecretRateLimiter::new()` in the lock handler is harmless and aligns with the "clean slate after lock" principle.

---

### P1-003: `JitDelivery::resolve()` TOCTOU between cache read and store fetch

**Cited location**: `core-secrets/src/jit.rs:43-71`
**Verdict**: VALID (reviewer's self-revised P3 assessment)
**Actual code** (`core-secrets/src/jit.rs:43-71`):
```rust
pub fn resolve<'a>(&'a self, key: &'a str) -> BoxFuture<'a, core_types::Result<SecureBytes>> {
    Box::pin(async move {
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(key)
                && cached.fetched_at.elapsed() < self.ttl
            {
                return Ok(cached.value.clone());
            }
        }
        let value = self.store.get(key).await?;
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                key.to_owned(),
                CachedSecret {
                    value: value.clone(),
                    fetched_at: Instant::now(),
                },
            );
        }
        Ok(value)
    })
}
```

**Analysis**: The reviewer correctly self-revises to P3. The cooperative single-threaded runtime makes this safe in practice. The TOCTOU gap is real but not exploitable.

**Adjusted severity**: P3 (informational, matches reviewer's revised assessment)
**Corrected remediation**: None needed beyond documentation.

---

### P1-004: `name_to_conn` mapping vulnerable to name squatting

**Cited location**: `core-ipc/src/server.rs:718-727`
**Verdict**: VALID
**Actual code** (`core-ipc/src/server.rs:718-727`):
```rust
if let EventKind::DaemonStarted { .. } = &msg.payload
    && let Some(ref name) = verified_name
{
    state.name_to_conn.write().await.insert(name.clone(), sender_conn_id);
    tracing::debug!(
        daemon_name = %name,
        conn_id = sender_conn_id,
        "name_to_conn mapping registered"
    );
}
```

**Analysis**: The `insert()` unconditionally overwrites. The reviewer correctly identifies that a second connection authenticating with the same private key would overwrite the first's routing. The prerequisite (compromising a daemon's private key) requires filesystem access to `$XDG_RUNTIME_DIR/pds/keys/`, which is mitigated by Landlock.

On disconnect, the old mapping is cleaned up (server.rs:595):
```rust
state.name_to_conn.write().await.retain(|_, cid| *cid != conn_id);
```

This means if the legitimate daemon disconnects, its mapping is removed. But if the attacker connects second while the legitimate daemon is still connected, the attacker's conn_id overwrites. The legitimate daemon's messages still route correctly (they use `name_to_conn` for unicast TO daemons, not FROM them), but confirmed RPCs sent TO the legitimate daemon now go to the attacker.

**Adjusted severity**: P1 (requires Noise IK key compromise, significant impact)
**Corrected remediation**: Reviewer's recommendations are sound. Reject duplicate name registration or disconnect the old connection.

---

### P1-005: Broadcast lock/unlock response sent AFTER correlated unicast response

**Cited location**: `daemon-secrets/src/main.rs:887-907`
**Verdict**: VALID
**Actual code** (`daemon-secrets/src/main.rs:897-907`):
```rust
send_response(ctx.client, msg, event, ctx.daemon_id).await?;

if let Some(notify) = broadcast
    && let Err(e) = ctx.client.publish(notify, SecurityLevel::Internal).await
{
    tracing::error!(
        audit = "security",
        error = %e,
        "lock/unlock broadcast failed — daemon-profile may have stale state"
    );
}
```

**Analysis**: The ordering is confirmed. The unicast response goes first (line 897), then the broadcast (line 900). A crash between these two operations is the concern. However, this requires an adversary who can trigger daemon-secrets crashes at precise sub-millisecond timing, which is far-fetched even under APT. The 30s reconciliation watchdog corrects this.

**Adjusted severity**: P2 (defense-in-depth ordering issue, mitigated by reconciliation)
**Corrected remediation**: Reorder broadcast before unicast. Simple, low-risk fix.

---

### P2-001: `SqlCipherStore` uses `std::sync::Mutex` -- no `Drop` guarantees for `pragma_rekey_clear()`

**Cited location**: `core-secrets/src/sqlcipher.rs:16,24`
**Verdict**: VALID
**Actual code** -- no `Drop` impl exists for `SqlCipherStore`. The struct definition at line 21-29:
```rust
pub struct SqlCipherStore {
    conn: Mutex<Connection>,
    entry_key: SecureBytes,
    db_path: PathBuf,
}
```

`SecureBytes` has zeroize-on-drop (for `entry_key`), but there is no `Drop` impl for `SqlCipherStore` itself, so `PRAGMA rekey = ''` is never called implicitly.

**Analysis**: Confirmed. The three explicit call sites cover all normal paths, but panic unwind would skip them. Under the current single-threaded architecture, a panic crashes the process entirely, so this is only relevant if the architecture changes.

**Adjusted severity**: P2 (defense-in-depth)
**Corrected remediation**: Add `Drop` impl. The reviewer's suggestion is correct.

---

### P2-002: `UnlockResponse` broadcast does not clear daemon-profile's `active_profiles`

**Cited location**: `daemon-profile/src/main.rs:670-673`
**Verdict**: VALID
**Actual code** (`daemon-profile/src/main.rs:670-673`):
```rust
EventKind::UnlockResponse { success: true } => {
    *locked = false;
    tracing::info!("secrets daemon unlocked, lock state updated");
    None
}
```

And the `LockResponse` handler (lines 676-681):
```rust
EventKind::LockResponse { success: true } => {
    *locked = true;
    active_profiles.clear();
    tracing::info!(audit = "security", "secrets locked, active profiles cleared");
    None
}
```

**Analysis**: The reviewer correctly identifies that `active_profiles.clear()` is missing from the `UnlockResponse` handler. The reviewer also correctly notes that the `LockResponse` handler already clears it, and the `DaemonStarted` handler for daemon-secrets (line 507-514) also clears it. So the gap is covered by other paths in normal operation.

The spec Section 3.5 step 3b requirement is violated, but practical impact is low.

**Adjusted severity**: P2 (spec violation, defense-in-depth)
**Corrected remediation**: Add `active_profiles.clear()` to the `UnlockResponse` handler. One-line fix.

---

### P2-003: No validation of `PRAGMA rekey = ''` success semantics

**Cited location**: `core-secrets/src/sqlcipher.rs:173-192`
**Verdict**: VALID
**Actual code**:
```rust
if let Err(e) = conn.execute_batch("PRAGMA rekey = '';") {
    tracing::warn!(
        path = %self.db_path.display(),
        error = %e,
        "PRAGMA rekey clear failed — C-level key buffer may not be zeroized"
    );
}
```

**Analysis**: The reviewer raises a legitimate concern. `PRAGMA rekey` in SQLCipher is documented to re-encrypt the database with a new key. Setting it to an empty string may either (a) re-encrypt with empty key (catastrophic), (b) be a no-op, or (c) clear the internal key buffer. The SQLCipher documentation says `PRAGMA rekey` with empty string removes encryption from the database. This is NOT the zeroization behavior intended.

If this is the actual SQLCipher behavior, then every lock/deactivate/shutdown call re-encrypts the database with no key, making all vault databases unencrypted on disk. This would be a P0 finding, not P2.

However, the actual behavior depends on the specific SQLCipher version and build linked by the `rusqlite` crate's `bundled-sqlcipher` feature. The reviewer correctly flags this as requiring empirical verification.

**Adjusted severity**: P0 or DISMISSED depending on empirical verification. If `PRAGMA rekey = ''` actually removes encryption, this is catastrophic. If rusqlite's bundled SQLCipher treats empty rekey as a no-op for key material clearing, it is P3.
**Corrected remediation**: The reviewer's recommendation is correct: empirically verify and add an integration test. If `PRAGMA rekey = ''` re-encrypts, switch to `PRAGMA key = ''` (which only clears the in-memory key without re-encrypting) or use raw `sqlite3_rekey()` FFI with a zero-length key.

---

### P2-004: `SecretList` request broadcasts profile existence to all bus subscribers

**Cited location**: `core-ipc/src/server.rs:776-791`
**Verdict**: PARTIAL
**Actual code** (`core-ipc/src/server.rs:776-791`):
```rust
// New request or broadcast — record for response routing and forward.
state.pending_requests.write().await.insert(msg.msg_id, sender_conn_id);

let conns = state.connections.read().await;
for (&cid, conn) in conns.iter() {
    if cid == sender_conn_id {
        continue;
    }
    if conn.security_clearance < msg.security_level {
        continue;
    }
    if conn.tx.try_send(stamped_payload.clone()).is_err() {
        tracing::warn!(conn_id = cid, "subscriber channel full, frame dropped");
    }
}
```

**Analysis**: The reviewer correctly identifies that new requests (no `correlation_id`) are broadcast to all matching subscribers. A `SecretList` at `SecurityLevel::SecretsOnly` would only reach subscribers with `SecretsOnly` clearance. Looking at KNOWN_DAEMONS, only `daemon-secrets` has `SecretsOnly` clearance. So `Internal`-clearance daemons (daemon-wm, daemon-launcher, etc.) would NOT receive the `SecretList` request because `Internal < SecretsOnly`.

The clearance filter at line 785 (`conn.security_clearance < msg.security_level`) prevents `Internal` daemons from seeing `SecretsOnly` messages. The reviewer's concern is invalid for `SecretsOnly`-level secret operations.

However, daemon-profile's host channel is registered with `Internal` clearance (daemon-profile/src/main.rs:208). So daemon-profile DOES see the request (it needs to for routing). But daemon-profile is the trusted bus server host, not a compromised daemon.

**Adjusted severity**: DISMISSED (clearance filtering already prevents the described information leakage to non-secrets daemons)
**Corrected remediation**: None needed. The clearance system already handles this.

---

### P3-001: Hardcoded 16 MiB max frame size

**Cited location**: `core-ipc/src/framing.rs`
**Verdict**: VALID
**Actual code** (`core-ipc/src/framing.rs:17`):
```rust
pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;
```

**Analysis**: Informational. No per-value size check at the `SecretsStore` level. A 16 MiB secret value would allocate significant memory. Low priority.

**Adjusted severity**: P3 (informational)
**Corrected remediation**: Add a max secret value size check in `SecretSet` handling as suggested.

---

### P3-002: `test_master_key()` in tests uses deterministic key derivation

**Cited location**: `daemon-secrets/src/main.rs:1291-1297`
**Verdict**: VALID
**Actual code** (`daemon-secrets/src/main.rs:1291-1297`):
```rust
fn test_master_key() -> SecureBytes {
    let mut key = vec![0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(13).wrapping_add(7);
    }
    SecureBytes::new(key)
}
```

**Analysis**: Test code only (`#[cfg(test)]`). Not a security issue.

**Adjusted severity**: P3 (informational)
**Corrected remediation**: None needed.

---

### P3-003: `check_secret_access()` has O(n) scan for daemon key lookup

**Cited location**: `daemon-secrets/src/acl.rs:61`
**Verdict**: VALID
**Actual code** (`daemon-secrets/src/acl.rs:61`):
```rust
allowed_keys.iter().any(|k| k == key)
```

**Analysis**: Linear scan over `Vec<String>`. ACL lists are expected to be small (< 100 keys per daemon). Not security-impacting.

**Adjusted severity**: P3 (informational)
**Corrected remediation**: None needed at current scale. Use `HashSet` if ACL lists grow.

---

## New Findings (Missed by First Reviewer)

### NEW-001: `ConfirmationGuard::drop()` uses `try_write()` with fallback spawn -- race condition

**File**: `core-ipc/src/server.rs:78-93`
**Actual code**:
```rust
impl Drop for ConfirmationGuard {
    fn drop(&mut self) {
        if let Ok(mut confirmations) = self.state.confirmations.try_write() {
            confirmations.remove(&self.correlation_id);
        } else {
            let id = self.correlation_id;
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                state.confirmations.write().await.remove(&id);
            });
        }
    }
}
```

**Analysis**: If `try_write()` fails (lock contended), the cleanup is deferred to a spawned task. Between `drop()` and the spawned task executing, a response matching the old `correlation_id` could arrive and be forwarded to a now-invalid `confirm_tx` channel. The receiver of that channel (`confirm_rx` in daemon-profile) has already moved on.

On a single-threaded runtime, `tokio::spawn` inside `Drop` is valid but the spawned task runs on the next poll cycle. The `try_write()` failure case requires the RwLock to be held by another task, which on a single-threaded runtime means the current task is in a synchronous code path within an `.await` boundary. This is unlikely but possible if `route_frame()` is processing a frame while the guard drops in `handle_bus_message()`.

**Severity**: P3 (informational -- the stale channel message is the same issue as P0-002 and is handled by type checking)
**Remediation**: Consider using `blocking_write()` instead of spawning, or accept the race as benign since the receiving code checks message types.

---

### NEW-002: `deactivate_profile()` calls `pragma_rekey_clear()` BEFORE `flush()`

**File**: `daemon-secrets/src/main.rs:131-138`
**Actual code**:
```rust
async fn deactivate_profile(&mut self, profile: &TrustProfileName) {
    self.active_profiles.remove(profile);
    if let Some(vault) = self.vaults.remove(profile) {
        vault.store().pragma_rekey_clear();
        vault.flush().await;
        drop(vault);
        tracing::info!(profile = %profile, "vault deactivated and key material zeroized");
    }
}
```

**Analysis**: `pragma_rekey_clear()` is called on line 134 before `vault.flush()` on line 135. The `flush()` call clears the JIT cache (SecureBytes are zeroized on drop from the HashMap). But the `pragma_rekey_clear()` clears the SQLCipher key FIRST. If there were any pending writes to the database after `pragma_rekey_clear()`, they would fail because the key is gone.

In practice, `flush()` only clears the in-memory cache (no database writes), so this ordering is functionally correct. But semantically, the SQLCipher connection's key is cleared while the JIT cache still holds decrypted secret values in memory. The `flush()` then drops those SecureBytes, which zeroize on drop.

The ordering in the shutdown path (`daemon-secrets/src/main.rs:408-411`) matches:
```rust
vault.store().pragma_rekey_clear();
vault.flush().await;
drop(vault);
```

This is consistent but violates a defense-in-depth principle: the JIT cache should be flushed BEFORE the database key is cleared, ensuring the minimal time window where both cleartext and key material coexist.

**Severity**: P3 (defense-in-depth ordering preference, no functional impact)
**Remediation**: Swap to `vault.flush().await; vault.store().pragma_rekey_clear();` for minimal cleartext lifetime.

---

### NEW-003: Secret value not zeroized after `vault.store().set()` in SecretSet handler

**File**: `daemon-secrets/src/main.rs:697-705`
**Actual code**:
```rust
#[cfg(not(feature = "ipc-field-encryption"))]
let store_value = value.as_bytes().to_vec();

let (success, denial) = match state.vault_for(profile) {
    Ok(vault) => {
        match vault.store().set(key, &store_value).await {
            Ok(()) => {
                vault.flush().await;
                (true, None)
            }
```

**Analysis**: `store_value` is a `Vec<u8>` copy of the secret value bytes. After `set()` completes, `store_value` is not explicitly zeroized. It is dropped at the end of the match arm, but `Vec<u8>` does not zeroize on drop. The `SqlCipherStore::set()` method at `sqlcipher.rs:228-251` does zeroize its internal copy:
```rust
let mut value = value.to_vec();
// ...
let ciphertext = self.encrypt_value(&value);
value.zeroize();
```

But the caller's `store_value` at `daemon-secrets/src/main.rs:698` is never zeroized. The original `SensitiveBytes` value in the `EventKind::SecretSet` message will be zeroized when dropped (line 26 of core-types), but `store_value` is a separate `Vec<u8>`.

**Severity**: P2 (secret value remains in heap memory after the handler completes)
**Remediation**: Add `store_value.zeroize()` after the match block, or use `SensitiveBytes` / `SecureBytes` throughout.

---

### NEW-004: `cmd_env` leaks secret values in process environment of child

**File**: `open-sesame/src/main.rs:1467-1479`
**Actual code**:
```rust
let mut cmd = std::process::Command::new(&command[0]);
cmd.args(&command[1..]);
cmd.env("SESAME_PROFILE", profile.as_ref());
for (env_name, value) in &env_vars {
    let val_str = String::from_utf8_lossy(value);
    cmd.env(env_name, val_str.as_ref());
}
```

**Analysis**: This is by design (`sesame env` exists to inject secrets as env vars). The zeroization at lines 1488-1490 covers the parent process copies. However, the child's `/proc/<pid>/environ` exposes all env vars to same-UID processes. This is inherent to the env-var injection pattern (same as `aws-vault`, `op run`, etc.) and is documented behavior, not a bug. Not a new finding.

---

## Summary Table

| Finding | Original | Verdict | Adjusted | Key reason |
|---|---|---|---|---|
| P0-001 | P0 | PARTIAL | P2 | Mutex poisoning unreachable on current single-threaded runtime (panic crashes process) |
| P0-002 | P0 | PARTIAL | P2 | Borrow checker prevents concurrency; stale message causes silent reconciliation skip, not corruption |
| P0-003 | P0 | VALID | P1 | Spec violation confirmed; mitigated by 30s watchdog (not immediate) |
| P1-001 | P1 | VALID | P2 | Clearance enforcement already blocks non-SecretsOnly daemons from issuing secret requests |
| P1-002 | P1 | PARTIAL | P3 | HashMap bounded to ~7 entries (fixed daemon set); GCRA handles stale timestamps correctly |
| P1-003 | P1 | VALID (self-revised) | P3 | Reviewer correctly self-revised; cooperative scheduling makes it safe |
| P1-004 | P1 | VALID | P1 | Unconditional overwrite confirmed; requires key compromise |
| P1-005 | P1 | VALID | P2 | Crash between unicast and broadcast requires sub-ms timing; mitigated by reconciliation |
| P2-001 | P2 | VALID | P2 | No Drop impl confirmed; only relevant if architecture changes to multi-threaded |
| P2-002 | P2 | VALID | P2 | Spec violation confirmed; covered by other paths in practice |
| P2-003 | P2 | VALID | P0/DISMISSED | PRAGMA rekey = '' may remove encryption entirely -- needs empirical verification |
| P2-004 | P2 | PARTIAL | DISMISSED | Clearance filtering prevents Internal-clearance daemons from seeing SecretsOnly messages |
| P3-001 | P3 | VALID | P3 | Informational |
| P3-002 | P3 | VALID | P3 | Test code only |
| P3-003 | P3 | VALID | P3 | Informational |
| NEW-001 | - | NEW | P3 | ConfirmationGuard drop race -- benign, handled by type checking |
| NEW-002 | - | NEW | P3 | pragma_rekey_clear before flush -- defense-in-depth ordering |
| NEW-003 | - | NEW | P2 | store_value Vec<u8> not zeroized after SecretSet |
