# Security Protocol Triage Analysis

Principal Staff Security Engineering -- Open Sesame v2

---

## Section 1: Finding Triage (Ranked by Exploitability)

### 1. SEC-001: Deactivation is cosmetic -- secrets accessible after profile deactivation

**Exploitability: TRIVIAL**

**Reproduction steps:**
```bash
sesame unlock
sesame profile activate work
sesame secret set -p work api-key  # store a secret
sesame profile deactivate work
sesame secret get -p work api-key  # RETURNS THE SECRET -- should be denied
```

**Code path:**

1. CLI sends `SecretGet { profile: "work", key: "api-key" }` via `open-sesame/src/main.rs:741-744`
2. `daemon-profile/src/main.rs:321-380` receives the frame on `host_rx`, decodes it, passes to `handle_bus_message` -- but `SecretGet` is NOT matched in `handle_bus_message` (line 464-648). It falls through to `_ => None` at line 647.
3. The frame was already routed by `core-ipc/src/server.rs:549-683` `route_frame()` which forwarded it to daemon-secrets (all connected subscribers at sufficient clearance).
4. `daemon-secrets/src/main.rs:498-583` handles `SecretGet`. Lock check passes at line 538. No active profile check exists.
5. `vault_for()` at `daemon-secrets/src/main.rs:85-105` lazily re-opens the vault because `self.vaults.contains_key(profile)` is false (deactivation removed it at line 109), so it re-derives the vault key and opens a fresh connection.

**Root cause:** `vault_for()` (line 85) has no `active_profiles` set to consult. `deactivate_profile()` (line 108) removes the vault from the `vaults` HashMap, but `vault_for()` happily re-creates it on the next access. There is no authorization gate -- only a resource cache.

---

### 2. SEC-007: Repeat unlock accepts any password

**Exploitability: TRIVIAL**

**Reproduction steps:**
```bash
sesame unlock        # enter correct password
sesame unlock        # enter WRONG password -- reports "Already unlocked." from CLI
                     # but if a raw IPC client sends UnlockRequest, daemon-secrets
                     # returns success: true
```

**Code path:**

`daemon-secrets/src/main.rs:449-467`:
```rust
EventKind::UnlockRequest { password } => {
    let outcome = if ctx.unlocked_state.is_some() {
        tracing::warn!("unlock requested but already unlocked");
        "already-unlocked"
    } else {
        // ... Argon2id derivation ...
    };
    audit_secret_access("unlock", msg.sender, "-", None, outcome);
    Some(EventKind::UnlockResponse { success: outcome != "failed" })
}
```

Line 467: `outcome != "failed"` evaluates to `true` when `outcome == "already-unlocked"`, so `UnlockResponse { success: true }` is returned. This leaks lock state to any bus client and violates the principle of least information.

**Note:** The CLI (`open-sesame/src/main.rs:509-515`) does a StatusRequest first and short-circuits with "Already unlocked." before sending UnlockRequest. But a direct IPC client (compromised daemon, raw socket) bypasses this.

---

### 3. SEC-003: No active-profile set in daemon-secrets

**Exploitability: TRIVIAL (same root as SEC-001)**

**Code path:**

`daemon-secrets/src/main.rs:71-81` -- `UnlockedState` struct:
```rust
struct UnlockedState {
    master_key: SecureBytes,
    vaults: HashMap<TrustProfileName, JitDelivery<SqlCipherStore>>,
    ttl: Duration,
    config_dir: PathBuf,
}
```

No `active_profiles: HashSet<TrustProfileName>` field exists. The `vaults` HashMap doubles as both a resource cache and an implicit "active set", but `vault_for()` re-populates it on demand, making it useless as a security boundary.

`ProfileActivate` handler (lines 745-761) calls `vault_for()` to open the vault but does not record activation in any authorization set. `ProfileDeactivate` handler (lines 763-777) calls `deactivate_profile()` which removes from `vaults`, but this is a resource cleanup, not a security revocation.

---

### 4. SEC-002: Activation/deactivation use fire-and-forget broadcasts

**Exploitability: REQUIRES-TIMING (race conditions under load)**

**Code path:**

`daemon-profile/src/activation.rs:62-71`:
```rust
// Step 2: Send ProfileActivate to daemon-secrets.
let activate_event = EventKind::ProfileActivate {
    profile_name: profile_name.clone(),
    target,
};
if let Err(e) = broadcast(bus, daemon_id, activate_event).await {
    rollback(&completed, target, profile_name, bus, audit, daemon_id).await;
    return Err(format!("failed to send ProfileActivate: {e}"));
}
completed.push(CompletedStep::SecretsVaultOpened);
```

Line 71: `CompletedStep::SecretsVaultOpened` is pushed immediately after the broadcast succeeds (line 67 checks only that `bus.publish()` did not error). There is no waiting for `ProfileActivateResponse` from daemon-secrets. The broadcast is fire-and-forget.

Similarly for deactivation at lines 119-129:
```rust
if let Err(e) = broadcast(bus, daemon_id, deactivate_event).await {
    // ...
}
completed.push(CompletedStep::SecretsJitFlushed);
completed.push(CompletedStep::SecretsVaultClosed);
```

Two completion steps are recorded without any confirmation that daemon-secrets actually processed the deactivation.

**The `broadcast()` function** (lines 155-164) calls `bus.publish()` which fans out to all subscribers including daemon-profile's own `host_rx` (filtered by the self-sender check at `daemon-profile/src/main.rs:334`). daemon-secrets receives it on its `BusClient.recv()` loop. But daemon-profile never waits for the correlated response.

---

### 5. SEC-004: Lock state drift between daemons

**Exploitability: REQUIRES-TIMING (broadcast drop under channel backpressure)**

**Code path:**

`daemon-secrets/src/main.rs:787-797`:
```rust
let broadcast = match &event {
    EventKind::UnlockResponse { success } => Some(EventKind::UnlockResponse { success: *success }),
    EventKind::LockResponse { success } => Some(EventKind::LockResponse { success: *success }),
    _ => None,
};

send_response(ctx.client, msg, event, ctx.daemon_id).await?;

if let Some(notify) = broadcast {
    ctx.client.publish(notify, SecurityLevel::Internal).await.ok();
}
```

Line 796: `.ok()` silently swallows any error from the broadcast. If the publish channel is full (256-entry mpsc buffer in `core-ipc/src/server.rs:223`), the broadcast is dropped and daemon-profile never learns about the lock/unlock state change.

`daemon-profile/src/main.rs:635-645` handles these broadcasts:
```rust
EventKind::UnlockResponse { success: true } => {
    *locked = false;
    // ...
}
EventKind::LockResponse { success: true } => {
    *locked = true;
    // ...
}
```

If the broadcast never arrives, `daemon-profile`'s `locked` bool diverges from reality.

---

### 6. SEC-005: Stale active_profiles after lock

**Exploitability: REQUIRES-AUTH (attacker must be able to trigger unlock after lock)**

**Code path:**

`daemon-secrets/src/main.rs:471-481` -- Lock handler:
```rust
EventKind::LockRequest => {
    if let Some(state) = ctx.unlocked_state.take() {
        drop(state); // SecureBytes zeroizes on drop.
        #[cfg(target_os = "linux")]
        keyring_delete().await;
        tracing::info!("secrets locked, master key zeroized");
    }
    // ...
}
```

`Option::take()` drops the entire `UnlockedState` including the `vaults` HashMap. This effectively clears daemon-secrets' implicit "active set" (the vaults map). So in daemon-secrets, lock DOES clear the vaults. However:

`daemon-profile/src/main.rs:641-644` -- LockResponse handler:
```rust
EventKind::LockResponse { success: true } => {
    *locked = true;
    tracing::info!("secrets daemon locked, lock state updated");
    None
}
```

**`active_profiles.clear()` is NOT called.** After unlock, daemon-profile still thinks previously-activated profiles are active. Any StatusRequest will report stale profiles. If the user unlocks and tries to access secrets for a "stale active" profile, daemon-profile will NOT send a new `ProfileActivate` (since it thinks the profile is already active), but daemon-secrets will lazily re-open the vault via `vault_for()` (SEC-001).

---

### 7. SEC-006: Daemon-secrets restart doesn't reset daemon-profile lock flag

**Exploitability: REQUIRES-TIMING (requires daemon-secrets crash/restart)**

**Code path:**

`daemon-profile/src/main.rs:466-550` -- `DaemonStarted` handler:

The entire handler deals with key revocation and re-registration after detecting a daemon restart via `daemon_tracker.track()`. But there is no code that sets `*locked = true` or calls `active_profiles.clear()` when the restarted daemon is "daemon-secrets".

When daemon-secrets restarts, it starts in a locked state (line 316: `let mut unlocked_state: Option<UnlockedState> = None`). But daemon-profile's `locked` bool (line 193: `let mut locked = true`) was set to `false` during the previous session's unlock and is never reset on restart detection.

---

## Section 2: Code Before & After (Per Finding)

### SEC-001 & SEC-003: Active Profile Authorization Gate

**BEFORE:** `daemon-secrets/src/main.rs:71-81`
```rust
struct UnlockedState {
    master_key: SecureBytes,
    vaults: HashMap<TrustProfileName, JitDelivery<SqlCipherStore>>,
    ttl: Duration,
    config_dir: PathBuf,
}
```

**AFTER:** `daemon-secrets/src/main.rs:71-82`
```rust
struct UnlockedState {
    master_key: SecureBytes,
    vaults: HashMap<TrustProfileName, JitDelivery<SqlCipherStore>>,
    /// Authorized profiles -- security boundary. vault_for() MUST refuse
    /// access for profiles not in this set.
    active_profiles: HashSet<TrustProfileName>,
    ttl: Duration,
    config_dir: PathBuf,
}
```

**Diff:** Added `active_profiles: HashSet<TrustProfileName>` field. Requires `use std::collections::HashSet;` (already imported at daemon-profile but not daemon-secrets -- add to imports at line 48).

---

**BEFORE:** `daemon-secrets/src/main.rs:83-105` -- `vault_for()`
```rust
fn vault_for(&mut self, profile: &TrustProfileName) -> core_types::Result<&JitDelivery<SqlCipherStore>> {
    if !self.vaults.contains_key(profile) {
        let vault_key = core_crypto::derive_vault_key(self.master_key.as_bytes(), profile);
        let db_path = self.config_dir.join("vaults").join(format!("{profile}.db"));
        // ... create dir, open store, insert ...
    }
    Ok(self.vaults.get(profile).expect("just inserted"))
}
```

**AFTER:**
```rust
fn vault_for(&mut self, profile: &TrustProfileName) -> core_types::Result<&JitDelivery<SqlCipherStore>> {
    if !self.active_profiles.contains(profile) {
        return Err(core_types::Error::Secrets(format!(
            "profile '{}' is not active -- access denied",
            profile
        )));
    }
    if !self.vaults.contains_key(profile) {
        let vault_key = core_crypto::derive_vault_key(self.master_key.as_bytes(), profile);
        let db_path = self.config_dir.join("vaults").join(format!("{profile}.db"));

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                core_types::Error::Secrets(format!(
                    "failed to create vault directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let store = SqlCipherStore::open(&db_path, &vault_key)?;
        let jit = JitDelivery::new(store, self.ttl);
        self.vaults.insert(profile.clone(), jit);
        tracing::info!(profile = %profile, path = %db_path.display(), "vault opened");
    }
    Ok(self.vaults.get(profile).expect("just inserted"))
}
```

**Diff:** Added `active_profiles.contains()` guard as the first check before any vault operation.

---

**BEFORE:** `daemon-secrets/src/main.rs:745-761` -- ProfileActivate handler
```rust
EventKind::ProfileActivate { profile_name, .. } => {
    let Some(state) = ctx.unlocked_state.as_mut() else {
        tracing::warn!(profile = %profile_name, "profile activate while locked");
        return send_response(ctx.client, msg, EventKind::ProfileActivateResponse { success: false }, ctx.daemon_id).await;
    };
    let success = match state.vault_for(profile_name) {
        Ok(_) => {
            tracing::info!(profile = %profile_name, "profile activated");
            true
        }
        Err(e) => {
            tracing::error!(profile = %profile_name, error = %e, "profile activation failed");
            false
        }
    };
    Some(EventKind::ProfileActivateResponse { success })
}
```

**AFTER:**
```rust
EventKind::ProfileActivate { profile_name, .. } => {
    let Some(state) = ctx.unlocked_state.as_mut() else {
        tracing::warn!(profile = %profile_name, "profile activate while locked");
        return send_response(ctx.client, msg, EventKind::ProfileActivateResponse { success: false }, ctx.daemon_id).await;
    };
    // Add to authorized set FIRST, then open vault.
    state.active_profiles.insert(profile_name.clone());
    let success = match state.vault_for(profile_name) {
        Ok(_) => {
            tracing::info!(
                audit = "security",
                profile = %profile_name,
                "profile activated -- added to active set"
            );
            true
        }
        Err(e) => {
            // Rollback: remove from active set on vault open failure.
            state.active_profiles.remove(profile_name);
            tracing::error!(profile = %profile_name, error = %e, "profile activation failed");
            false
        }
    };
    Some(EventKind::ProfileActivateResponse { success })
}
```

**Diff:** `state.active_profiles.insert()` before `vault_for()`. Rollback on failure.

---

**BEFORE:** `daemon-secrets/src/main.rs:107-120` -- `deactivate_profile()`
```rust
async fn deactivate_profile(&mut self, profile: &TrustProfileName) -> core_types::Result<()> {
    if let Some(vault) = self.vaults.remove(profile) {
        vault.flush().await;
        drop(vault);
        tracing::info!(profile = %profile, "vault deactivated");
        Ok(())
    } else {
        Err(core_types::Error::NotFound(format!(
            "profile '{profile}' is not active"
        )))
    }
}
```

**AFTER:**
```rust
async fn deactivate_profile(&mut self, profile: &TrustProfileName) -> core_types::Result<()> {
    // Remove from authorized set FIRST -- revoke access before cleanup.
    if !self.active_profiles.remove(profile) {
        return Err(core_types::Error::NotFound(format!(
            "profile '{profile}' is not in active set"
        )));
    }
    if let Some(vault) = self.vaults.remove(profile) {
        vault.flush().await;
        // SqlCipherStore closes DB on drop. entry_key (SecureBytes) zeroizes on drop.
        drop(vault);
        tracing::info!(
            audit = "security",
            profile = %profile,
            "vault deactivated -- removed from active set, vault key zeroized"
        );
    } else {
        tracing::info!(
            audit = "security",
            profile = %profile,
            "profile deauthorized -- no vault was open"
        );
    }
    Ok(())
}
```

**Diff:** `active_profiles.remove()` is the first operation. Success even if vault was not open (deauthorization is the security-critical action).

---

**BEFORE:** `daemon-secrets/src/main.rs:847-877` -- `unlock()` return value
```rust
Ok(UnlockedState {
    master_key,
    vaults: HashMap::new(),
    ttl: Duration::from_secs(ttl),
    config_dir: config_dir.to_path_buf(),
})
```

**AFTER:**
```rust
Ok(UnlockedState {
    master_key,
    vaults: HashMap::new(),
    active_profiles: HashSet::new(),
    ttl: Duration::from_secs(ttl),
    config_dir: config_dir.to_path_buf(),
})
```

**Diff:** Initialize `active_profiles` as empty on unlock. Same change at line 847 (keyring fast path).

---

### SEC-007: Unlock Rejects When Already Unlocked

**BEFORE:** `daemon-secrets/src/main.rs:449-467`
```rust
EventKind::UnlockRequest { password } => {
    let outcome = if ctx.unlocked_state.is_some() {
        tracing::warn!("unlock requested but already unlocked");
        "already-unlocked"
    } else {
        match unlock(password.as_bytes(), ctx.config_dir, ctx.ttl).await {
            Ok(state) => {
                tracing::info!("secrets unlocked");
                *ctx.unlocked_state = Some(state);
                "success"
            }
            Err(e) => {
                tracing::error!(error = %e, "unlock failed");
                "failed"
            }
        }
    };
    audit_secret_access("unlock", msg.sender, "-", None, outcome);
    Some(EventKind::UnlockResponse { success: outcome != "failed" })
}
```

**AFTER:**
```rust
EventKind::UnlockRequest { password } => {
    let outcome = if ctx.unlocked_state.is_some() {
        tracing::warn!(
            audit = "security",
            requester = %msg.sender,
            "unlock request rejected -- already unlocked"
        );
        "rejected-already-unlocked"
    } else {
        match unlock(password.as_bytes(), ctx.config_dir, ctx.ttl).await {
            Ok(state) => {
                tracing::info!("secrets unlocked");
                *ctx.unlocked_state = Some(state);
                "success"
            }
            Err(e) => {
                tracing::error!(error = %e, "unlock failed");
                "failed"
            }
        }
    };
    audit_secret_access("unlock", msg.sender, "-", None, outcome);
    Some(EventKind::UnlockResponse { success: outcome == "success" })
}
```

**Diff:** Line 467 changed from `outcome != "failed"` to `outcome == "success"`. Only explicit success returns `true`. The "already-unlocked" case now returns `success: false`.

---

### SEC-005: Lock Clears active_profiles in daemon-profile

**BEFORE:** `daemon-profile/src/main.rs:641-644`
```rust
EventKind::LockResponse { success: true } => {
    *locked = true;
    tracing::info!("secrets daemon locked, lock state updated");
    None
}
```

**AFTER:**
```rust
EventKind::LockResponse { success: true } => {
    *locked = true;
    active_profiles.clear();
    tracing::info!(
        audit = "security",
        "secrets daemon locked -- lock state updated, active profiles cleared"
    );
    None
}
```

**Diff:** Added `active_profiles.clear()`.

---

### SEC-004: Lock/Unlock Broadcast Error Handling

**BEFORE:** `daemon-secrets/src/main.rs:796`
```rust
ctx.client.publish(notify, SecurityLevel::Internal).await.ok();
```

**AFTER:**
```rust
if let Err(e) = ctx.client.publish(notify, SecurityLevel::Internal).await {
    tracing::error!(
        audit = "security",
        error = %e,
        "lock/unlock broadcast to daemon-profile FAILED -- state may diverge"
    );
}
```

**Diff:** Replace `.ok()` with error-level logging. The correlated response already reached the CLI, so this is observability, not protocol failure.

---

### SEC-006: Daemon-secrets Restart Resets Lock State

**BEFORE:** `daemon-profile/src/main.rs:466-550` -- `DaemonStarted` handler (excerpt showing the gap -- no lock reset code exists)

**AFTER:** Add after `daemon_tracker.track()` check, before the key revocation block (insert at ~line 473):
```rust
EventKind::DaemonStarted { daemon_id: announced_id, capabilities, .. } => {
    let name = msg.verified_sender_name.clone()
        .or_else(|| capabilities.first().cloned())
        .unwrap_or_else(|| "unknown".into());

    if let Some(old_id) = daemon_tracker.track(&name, *announced_id) {
        // If daemon-secrets restarted, it is now locked with no active profiles.
        if name == "daemon-secrets" {
            *locked = true;
            active_profiles.clear();
            tracing::warn!(
                audit = "security",
                event_type = "daemon-secrets-restart",
                old_id = %old_id,
                new_id = %announced_id,
                "daemon-secrets restarted -- resetting lock=true and clearing active profiles"
            );
        }

        // ... existing key revocation logic ...
    }
    None
}
```

**Diff:** Added `if name == "daemon-secrets"` guard that resets `locked` and clears `active_profiles`.

---

### SEC-002: Confirmed RPC for Activation

**BEFORE:** `daemon-profile/src/activation.rs:62-71`
```rust
let activate_event = EventKind::ProfileActivate {
    profile_name: profile_name.clone(),
    target,
};
if let Err(e) = broadcast(bus, daemon_id, activate_event).await {
    rollback(&completed, target, profile_name, bus, audit, daemon_id).await;
    return Err(format!("failed to send ProfileActivate: {e}"));
}
completed.push(CompletedStep::SecretsVaultOpened);
```

**AFTER:** This requires the most significant architectural change. The function signature must accept a channel to receive correlated responses:

```rust
pub async fn activate<W: std::io::Write>(
    target: ProfileId,
    profile_name: &TrustProfileName,
    bus: &BusServer,
    audit: &mut AuditLogger<W>,
    daemon_id: DaemonId,
    host_rx: &mut mpsc::Receiver<Vec<u8>>,
    rpc_timeout: Duration,
) -> Result<u32, String> {
    let start = Instant::now();
    let mut completed: Vec<CompletedStep> = Vec::new();

    // Step 1: Emit ActivationBegun broadcast (informational).
    let begun_event = EventKind::ProfileActivationBegun {
        target,
        trigger: format!("explicit activation of {profile_name}"),
    };
    if let Err(e) = broadcast(bus, daemon_id, begun_event).await {
        return Err(format!("failed to emit ActivationBegun: {e}"));
    }
    completed.push(CompletedStep::ActivationBegunEmitted);

    // Step 2: Send ProfileActivate to daemon-secrets as broadcast,
    // then wait for correlated ProfileActivateResponse.
    let activate_event = EventKind::ProfileActivate {
        profile_name: profile_name.clone(),
        target,
    };
    let msg = Message::new(daemon_id, activate_event, SecurityLevel::Internal, bus.epoch());
    let msg_id = msg.msg_id;
    let payload = core_ipc::encode_frame(&msg).map_err(|e| e.to_string())?;
    bus.publish(&payload, SecurityLevel::Internal).await;

    // Wait for correlated response with timeout.
    let confirmed = wait_for_correlated_response(
        host_rx, msg_id, rpc_timeout,
    ).await;

    match confirmed {
        Some(EventKind::ProfileActivateResponse { success: true }) => {
            completed.push(CompletedStep::SecretsVaultOpened);
        }
        Some(EventKind::ProfileActivateResponse { success: false }) => {
            rollback(&completed, target, profile_name, bus, audit, daemon_id).await;
            return Err("daemon-secrets rejected profile activation".into());
        }
        _ => {
            // Timeout or unexpected response -- fail closed.
            rollback(&completed, target, profile_name, bus, audit, daemon_id).await;
            return Err("timeout waiting for daemon-secrets activation confirmation".into());
        }
    }

    // Step 3: Emit ProfileActivated broadcast (informational).
    let duration_ms = start.elapsed().as_millis() as u32;
    let activated_event = EventKind::ProfileActivated {
        target,
        duration_ms,
    };
    if let Err(e) = broadcast(bus, daemon_id, activated_event).await {
        rollback(&completed, target, profile_name, bus, audit, daemon_id).await;
        return Err(format!("failed to emit ProfileActivated: {e}"));
    }
    completed.push(CompletedStep::ActivationCompletedEmitted);

    // Step 4: Audit entry.
    if let Err(e) = audit.append(core_profile::AuditAction::ProfileActivated {
        target,
        duration_ms,
    }) {
        tracing::error!(error = %e, "failed to write activation audit entry");
    }

    Ok(duration_ms)
}

/// Wait for a correlated response on host_rx, filtering out unrelated messages.
async fn wait_for_correlated_response(
    host_rx: &mut mpsc::Receiver<Vec<u8>>,
    expected_correlation: uuid::Uuid,
    timeout: Duration,
) -> Option<EventKind> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        tokio::select! {
            frame = host_rx.recv() => {
                let Some(frame) = frame else { return None; };
                let Ok(msg) = core_ipc::decode_frame::<Message<EventKind>>(&frame) else {
                    continue;
                };
                if msg.correlation_id == Some(expected_correlation) {
                    return Some(msg.payload);
                }
                // Not our response -- discard (or re-queue in production).
            }
            _ = tokio::time::sleep_until(deadline) => {
                return None;
            }
        }
    }
}
```

**Diff:** Replaced fire-and-forget `broadcast()` with `bus.publish()` + `wait_for_correlated_response()`. The function now requires `host_rx` and `rpc_timeout` parameters, which requires updating the call sites in `daemon-profile/src/main.rs:576` and `:603`.

**Note on approach:** This uses the "simpler" Option B from the omnibus (section 4.6) -- filtering `host_rx` for the correlated response. This avoids adding new API to `core-ipc/src/server.rs`. The tradeoff is that unrelated messages arriving on `host_rx` during the wait are discarded. In production, a bounded re-queue buffer should be added, but for the security fix the fail-closed behavior is acceptable.

---

## Section 3: State Machine Models

### ACTIVATE Protocol

**CURRENT state machine:**
```
                      CLI
                       |
            ProfileActivate
                       |
                       v
    +------------------+------------------+
    |           daemon-profile             |
    |                                      |
    |  [ANY] --broadcast(ProfileActivate)-> [ASSUMED_ACTIVE]
    |         (no confirmation waited)     |
    |                                      |
    |  UNGUARDED: success recorded         |
    |  regardless of daemon-secrets state  |
    +--------------------------------------+
                       |
            broadcast (fire-and-forget)
                       |
                       v
    +------------------+------------------+
    |           daemon-secrets             |
    |                                      |
    |  [RECEIVED] --vault_for()-> [VAULT_OPEN]
    |                                      |
    |  UNGUARDED: no active_profiles set   |
    |  vault opens for ANY profile name    |
    +--------------------------------------+
```

**TARGET state machine:**
```
    CLI
     |
     | ProfileActivate
     v
+----+--------------------------------------------+
|  daemon-profile                                  |
|                                                  |
|  [IDLE]                                          |
|    | broadcast ProfileActivationBegun            |
|    v                                             |
|  [BEGUN]                                         |
|    | publish ProfileActivate to bus              |
|    | wait_for_correlated_response(timeout=5s)    |
|    v                                             |
|  [AWAITING_CONFIRM]---timeout--> [FAILED]        |
|    | ProfileActivateResponse                     |
|    v                                             |
|  {success?}                                      |
|    |yes                    |no                   |
|    v                       v                     |
|  [CONFIRMED]            [FAILED]                 |
|    | insert into           | do NOT insert       |
|    | active_profiles       | rollback             |
|    | broadcast Activated   |                      |
|    | audit entry           |                      |
|    v                       v                     |
|  [ACTIVE]              [IDLE]                    |
+--------------------------------------------------+
                    |
                    | ProfileActivate (unicast/broadcast)
                    v
+---------------------------------------------------+
|  daemon-secrets                                    |
|                                                    |
|  [RECEIVED]                                        |
|    | GUARD: unlocked_state.is_some()               |
|    v                                               |
|  [AUTHORIZED]                                      |
|    | active_profiles.insert(profile)               |
|    | vault_for(profile) -- lazy open               |
|    v                                               |
|  {vault_open?}                                     |
|    |yes                     |no                    |
|    v                        v                      |
|  [SUCCESS]               [FAILED]                  |
|    | respond success:true    | active_profiles     |
|    |                         |   .remove(profile)  |
|    |                         | respond success:false|
+---------------------------------------------------+
```

---

### DEACTIVATE Protocol

**CURRENT state machine:**
```
    CLI
     |
     v
  daemon-profile
     |
     | broadcast(ProfileDeactivate)  -- fire-and-forget
     | record SecretsJitFlushed + SecretsVaultClosed immediately
     | UNGUARDED: no confirmation
     |
     v
  daemon-secrets
     |
     | deactivate_profile() -- removes from vaults HashMap
     | UNGUARDED: vault_for() will re-open on next access
```

**TARGET state machine:**
```
    CLI
     |
     v
  daemon-profile
     |
     | [IDLE]
     |   broadcast DeactivationBegun
     |   publish ProfileDeactivate
     |   wait_for_correlated_response(timeout=5s)
     | [AWAITING_CONFIRM]---timeout--> [RECONCILE]
     |   | ProfileDeactivateResponse           |
     |   v                                     | query SecretsState
     | {success?}                              | reconcile local state
     |   |yes           |no                    |
     |   v              v                      v
     | [CONFIRMED]   [FAILED]             [RECONCILED]
     |   remove from   leave in
     |   active_profs  active_profs
     |   broadcast     return error
     |   Deactivated
     |
     v
  daemon-secrets
     |
     | [RECEIVED]
     |   GUARD: unlocked_state.is_some()
     |   GUARD: active_profiles.contains(profile)
     |   active_profiles.remove(profile) -- FIRST
     |   vaults.remove(profile) -- flush + drop
     |   respond success:true
```

---

### LOCK Protocol

**CURRENT state machine:**
```
  daemon-secrets:
    [UNLOCKED] --LockRequest--> unlocked_state.take() --> drop(state)
                                 keyring_delete()
                                 respond LockResponse{success:true}
                                 broadcast LockResponse -- .ok() swallows errors
                                 UNGUARDED: no active_profiles.clear() (none exists)

  daemon-profile:
    [TRACKING] --LockResponse broadcast--> *locked = true
                                           UNGUARDED: active_profiles NOT cleared
```

**TARGET state machine:**
```
  daemon-secrets:
    [UNLOCKED]
      | LockRequest
      v
    [LOCKING]
      | state.active_profiles.clear()   <-- explicit clear
      | unlocked_state.take()           <-- drops vaults + master key
      | keyring_delete()
      | respond LockResponse{success:true}
      | publish LockResponse broadcast (log error on failure)
      v
    [LOCKED]

  daemon-profile:
    [TRACKING_UNLOCKED]
      | LockResponse{success:true} broadcast
      v
    [LOCKING]
      | *locked = true
      | active_profiles.clear()         <-- NEW
      v
    [TRACKING_LOCKED]
```

---

### UNLOCK Protocol

**CURRENT state machine:**
```
  daemon-secrets:
    [LOCKED] --UnlockRequest-->
      if already unlocked: return success:true  <-- BUG (SEC-007)
      else: Argon2id derive, set unlocked_state
            respond UnlockResponse{success:true}
            broadcast -- .ok()

  daemon-profile:
    [TRACKING_LOCKED] --UnlockResponse{success:true} broadcast-->
      *locked = false
      UNGUARDED: active_profiles not touched (stale from previous session)
```

**TARGET state machine:**
```
  daemon-secrets:
    [LOCKED]
      | UnlockRequest
      v
    {already unlocked?}
      |yes                              |no
      v                                 v
    respond success:false             [DERIVING]
    (fail closed, no info leak)         | Argon2id / keyring fast-path
                                        | set unlocked_state with EMPTY active_profiles
                                        | respond success:true
                                        | publish broadcast (log error on failure)
                                        v
                                      [UNLOCKED, 0 active profiles]

  daemon-profile:
    [TRACKING_LOCKED]
      | UnlockResponse{success:true}
      v
    [TRACKING_UNLOCKED]
      | *locked = false
      | active_profiles.clear()       <-- ensure clean slate
```

---

## Section 4: Discovery Resolution

### DISC-001: Can BusServer resolve daemon name to conn_id?

**Resolution:** Yes. `ClearanceRegistry::find_by_name()` (`core-ipc/src/registry.rs:101-103`) returns `Option<(&[u8; 32], &DaemonClearance)>`. However, this maps pubkey to name, not name to conn_id. The conn_id is stored in `ServerState::connections` (`core-ipc/src/server.rs:48-52`), keyed by conn_id. To find a conn_id by name, you would need to iterate `connections` and match on `verified_name`. There is no direct `name -> conn_id` method.

**Impact on implementation:** For confirmed RPC, the simpler approach (Option B -- filter `host_rx`) is preferable. daemon-profile already receives all bus messages on `host_rx`. It can publish the activation request as a broadcast, then filter `host_rx` for the correlated response. No new `BusServer` API needed.

### DISC-002: Does pending_request tracking work for server-initiated messages?

**Resolution:** `pending_requests` is populated by `route_frame()` at `core-ipc/src/server.rs:668`: `state.pending_requests.write().await.insert(msg.msg_id, sender_conn_id)`. This records the originating conn_id for response routing. For server-initiated messages published via `bus.publish()`, `route_frame()` is NOT called (publish goes directly to subscriber channels at line 274-294). So `pending_requests` is NOT populated for server-initiated messages.

**Impact on implementation:** daemon-profile cannot use `take_pending_request()` for responses to its own published messages. It must filter `host_rx` directly (Option B).

### DISC-003: Simplest confirmed RPC mechanism for activation.rs?

**Resolution:** Option B -- filter `host_rx` for correlated response. This requires:
1. Passing `host_rx: &mut mpsc::Receiver<Vec<u8>>` into `activate()` and `deactivate()`
2. Publishing the request with a known `msg_id`
3. Filtering received frames for matching `correlation_id`
4. Timeout via `tokio::time::sleep`

**Impact on implementation:** The call sites in `daemon-profile/src/main.rs:576` and `:603` must pass `&mut host_rx` to `activation::activate()` and `activation::deactivate()`. This requires restructuring the `tokio::select!` loop slightly -- the `host_rx.recv()` arm cannot be active while activation is borrowing `host_rx`. This is solvable by making activation a synchronous sub-state within the message handling path (it already is -- the handler awaits activation completion before returning to the select loop).

### DISC-004: Does SqlCipherStore zeroize key on drop?

**Resolution:** `SqlCipherStore` (`core-secrets/src/sqlcipher.rs:21-30`) holds:
- `conn: Mutex<Connection>` -- rusqlite `Connection`. On drop, `Connection` calls `sqlite3_close()` via the rusqlite FFI. SQLCipher's `sqlite3_close()` does NOT zeroize the key from its internal memory (the key is freed but not zeroed).
- `entry_key: SecureBytes` -- this IS zeroized on drop (SecureBytes zeroize-on-drop at `core-crypto/src/secure_bytes.rs:64-91`).

The vault_key passed to `SqlCipherStore::open()` (line 45) is used to set `PRAGMA key` (line 61) and then the `hex_key` and `pragma_sql` strings are explicitly zeroized (lines 67-68). The vault_key itself is a `SecureBytes` owned by the caller (`vault_for()`), created as a local at line 87 of `daemon-secrets/src/main.rs`. It goes out of scope after `SqlCipherStore::open()` returns and is zeroized on drop.

**Impact on implementation:** The vault_key is properly zeroized. The entry_key is properly zeroized. The SQLCipher internal key buffer (inside rusqlite/SQLCipher C library) is NOT explicitly zeroized. This is a residual risk but requires `sqlite3_rekey("")` or a custom FFI call to address. This is acceptable for Phase 5 as a known residual -- document it and track as a future hardening item.

### DISC-005: Does JitDelivery hold derived key material?

**Resolution:** `JitDelivery` (`core-secrets/src/jit.rs:27-31`) holds:
- `store: S` (the `SqlCipherStore` -- holds `entry_key: SecureBytes`)
- `cache: tokio::sync::RwLock<HashMap<String, CachedSecret>>` -- cached **plaintext** secret values as `SecureBytes`
- `ttl: Duration`

The cache holds `CachedSecret { value: SecureBytes, fetched_at: Instant }`. The `value` is `SecureBytes` (zeroize-on-drop). `flush()` (line 76-79) calls `cache.clear()` which drops all entries, triggering zeroization of each `SecureBytes`.

JitDelivery does NOT hold any key material directly -- only the `SqlCipherStore` (via `store` field) which holds the `entry_key`.

**Impact on implementation:** `flush()` properly zeroizes cached plaintext. `drop(vault)` in `deactivate_profile()` drops the `JitDelivery`, which drops the `SqlCipherStore`, which zeroizes `entry_key`. The cache is also dropped, zeroizing all cached secrets. Current behavior is correct.

### DISC-006: Can SQLCipher's internal key buffer be force-zeroized?

**Resolution:** SQLCipher's internal key is stored in `codec->pass` and `codec->keyLength`. SQLCipher provides `sqlcipher_codec_ctx_get_pass()` and related functions, but these are internal C APIs not exposed by rusqlite. The only way to force zeroization is:
1. `PRAGMA rekey = '';` -- changes the key to empty (re-encrypts the DB), but this is destructive and slow.
2. `sqlite3_close()` (on Connection drop) frees the codec context but does NOT explicitly zero the memory.

**Impact on implementation:** This is a residual risk in the SQLCipher C library layer. Mitigated by: (a) Landlock preventing other processes from reading daemon-secrets' memory, (b) seccomp preventing ptrace, (c) `MADV_DONTDUMP` on the master key. Track as a known residual.

### DISC-007: Is there a sentinel value to validate Argon2id derivation?

**Resolution:** Yes. `SqlCipherStore::open()` (line 96-101) executes `SELECT count(*) FROM sqlite_master` after setting the PRAGMA key. If the derived key is wrong, SQLCipher will fail to decrypt any page and this query will error. The `unlock()` function at `daemon-secrets/src/main.rs:832-878` does NOT open any vault during unlock -- vaults are opened lazily. So there is no sentinel check during the unlock itself.

However, the keyring fast-path (line 841-854) uses AES-256-GCM decryption with the KEK, and GCM tag verification rejects wrong passwords (line 1137-1144). The slow path (Argon2id) produces a master key, but there is no immediate validation that the derived key is correct -- the error surfaces only when a vault is first opened.

**Impact on implementation:** For Phase 2 (D-004), consider adding a sentinel check: derive a "canary" key from the master key via BLAKE3 with context "pds v1 unlock-canary", encrypt a known value with it during first unlock, and verify during subsequent unlocks. This is a defense-in-depth measure -- the current behavior is not strictly a security vulnerability (wrong password just means vaults won't open), but it provides better UX.

### DISC-008: Does Error::AccessDenied variant exist in core-types?

**Resolution:** No. `core-types/src/lib.rs:796-842` defines the `Error` enum. There is no `AccessDenied` variant. The closest are:
- `Error::Secrets(String)` -- used for vault errors
- `Error::IsolationDenied { resource: String }` -- for profile isolation
- `EventKind::AccessDenied { reason: String }` -- exists as an IPC event (line 591-593)

**Impact on implementation:** For the `vault_for()` active profile check, use `Error::Secrets("profile 'X' is not active -- access denied")`. Adding a dedicated `Error::AccessDenied` variant is cleaner but NOT required for the security fix -- it's a code quality improvement that can be done in the same PR or deferred.

### DISC-009: Exact routing path of LockRequest

**Resolution:** Traced from CLI:

1. CLI `cmd_lock()` (`open-sesame/src/main.rs:556-570`) calls `rpc(&client, EventKind::LockRequest, SecurityLevel::SecretsOnly)`.
2. `rpc()` (line 445-465) calls `client.request()` which sends via the BusClient's encrypted socket.
3. The frame arrives at `core-ipc/src/server.rs:470-473` (`transport.read_encrypted_frame`), decoded, then `route_frame()` is called.
4. `route_frame()` (line 549-683) has no `correlation_id` (new request), so it records `pending_requests.insert(msg.msg_id, sender_conn_id)` at line 668, then broadcasts to all subscribers at lines 670-681.
5. daemon-profile receives on `host_rx` (line 321). `handle_bus_message` does NOT match `LockRequest` (falls through to `_ => None` at line 647). So daemon-profile does NOT handle or forward LockRequest.
6. daemon-secrets receives via `client.recv()` (line 325). Its handler at line 471-481 processes it.
7. daemon-secrets responds with `LockResponse` which goes through `send_response()` (line 793) -- this sends a correlated response via `client.send()`.
8. The response arrives at `route_frame()` in the server. Since it has a `correlation_id`, it is unicast back to the CLI's conn_id via `pending_requests` (line 648-665).
9. daemon-secrets ALSO broadcasts `LockResponse` at line 795-797, which daemon-profile receives.

**Impact on implementation:** LockRequest goes directly from CLI through the bus to daemon-secrets. daemon-profile is a passive observer via the broadcast. This means daemon-profile's lock state tracking depends entirely on the broadcast succeeding -- reinforcing the need for SEC-004 fix (error logging) and the reconciliation protocol (D-006).

---

## Section 5: Implementation Dependency Graph

```
D-001: Active Profile Gate in daemon-secrets
  |
  +--> D-007: Test Suite (blocked by D-001)
  |
  +--> D-002: Confirmed RPC for Activation (can proceed in parallel)
  |      |
  |      +--> D-007: Test Suite (integration tests blocked by D-002)
  |
  +--> D-004: Unlock Hardening (independent, can proceed in parallel)
  |      |
  |      +--> D-007: Test Suite
  |
  +--> D-003: Lock State Consistency (depends on D-001 for active_profiles field)
  |      |
  |      +--> D-006: State Reconciliation (depends on D-003)
  |      |      |
  |      |      +--> D-007: Test Suite
  |      |
  |      +--> D-007: Test Suite
  |
  +--> D-005: Vault Key Zeroization (independent audit, low implementation cost)
         |
         +--> D-007: Test Suite
```

**Critical path:** D-001 -> D-003 -> D-006 -> D-007

**Estimated file count and line count per deliverable:**

| Deliverable | Files Modified | Est. Lines Changed | Est. Lines Added |
|---|---|---|---|
| D-001 | 1 (daemon-secrets/src/main.rs) | ~60 | ~30 |
| D-002 | 2 (activation.rs, daemon-profile/src/main.rs) | ~80 | ~60 |
| D-003 | 2 (daemon-profile/src/main.rs, daemon-secrets/src/main.rs) | ~15 | ~15 |
| D-004 | 1 (daemon-secrets/src/main.rs) | ~3 | ~5 |
| D-005 | 0 (audit only; no code changes needed -- SecureBytes already handles zeroization) | 0 | 0 |
| D-006 | 3 (core-types/src/lib.rs, daemon-secrets/src/main.rs, daemon-profile/src/main.rs) | ~10 | ~50 |
| D-007 | 1-2 (new test files or in-file unit tests) | 0 | ~300 |

**Total estimate:** ~5 files modified, ~160 lines changed, ~460 lines added.

---

## Section 6: Risk Assessment

### What can go wrong during implementation

1. **Activation message routing breakage (D-002):** Changing `activation.rs` to filter `host_rx` means messages received during the wait are discarded. If another daemon sends a critical message (e.g., `DaemonStarted` for crash detection), it will be lost. **Mitigation:** Buffer non-matching messages during the wait and re-inject after. Alternatively, use a dedicated channel for daemon-secrets responses separate from the general `host_rx`.

2. **Deadlock on host_rx borrow (D-002):** The `tokio::select!` loop in `daemon-profile/src/main.rs:288-437` reads from `host_rx`. If `activation::activate()` also borrows `host_rx`, the select loop cannot proceed. **Mitigation:** The activation handler runs synchronously within the `host_rx.recv()` arm (line 321-380), so `host_rx` is already consumed. The activation function can take ownership of `host_rx` during the call and return it. Alternatively, split the channel.

3. **Backward compatibility of UnlockedState (D-001):** Adding `active_profiles` to `UnlockedState` changes its construction sites. There are 3 construction sites in `unlock()` (2 for keyring fast-path + 1 for slow path). All must be updated. Missing one causes a compile error (Rust enforces exhaustive struct construction), so this is a compile-time-caught error, not a runtime risk.

4. **SEC-007 fix breaking CLI workflow (D-004):** Changing `success: outcome == "success"` means the CLI's `cmd_unlock()` will receive `success: false` for the "already-unlocked" case. The CLI already checks status first (line 509-515) and prints "Already unlocked." before sending UnlockRequest. But if the status check races with another client's lock, the CLI might send UnlockRequest to an already-unlocked daemon and get a failure. **Mitigation:** The CLI should handle `success: false` from unlock gracefully -- check status again to determine if the failure was "already unlocked" vs "wrong password".

### What regressions to watch for

1. **`sesame init` flow:** The init command (`open-sesame/src/init.rs`) calls unlock and activate during first-time setup. Verify that the init flow still works with the new active_profiles gate.

2. **Config hot-reload:** The config watcher sends `ConfigReloaded` events. Verify that config reload does not clear `active_profiles`.

3. **Key rotation:** The hourly key rotation (lines 294-312) reconnects daemons. Verify that reconnection does not trigger a false `DaemonStarted` that resets lock state.

4. **`sesame env` command:** This command fetches all secrets for a profile. Verify it still works after the active profile gate (requires profile to be activated first).

### Rollback plan

Each phase is independently deployable and independently revertible:

- **Phase 1 (D-001):** Revert the `active_profiles` field addition. Since it's a new field with no serialized state, reverting is a clean `git revert`.
- **Phase 2 (D-003, D-004):** Revert the LockResponse handler change and the unlock guard. These are 1-3 line changes.
- **Phase 3 (D-002):** Revert `activation.rs` to the broadcast-based approach. This is the riskiest phase -- test extensively before merging.
- **Phase 4 (D-006):** Revert the new EventKind variants and reconciliation logic.

The recommended deployment order matches the omnibus phases: Phase 1 first (fixes the P0 vulnerability with minimal blast radius), then Phase 2 (lock/unlock hardening), then Phase 3 (confirmed RPC), then Phase 4 (reconciliation). Each phase should be a separate PR with its own test coverage.
