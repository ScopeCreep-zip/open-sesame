//! IPC message dispatch: routes inbound events to handler modules.

use crate::crud;
use crate::rate_limit::SecretRateLimiter;
use crate::unlock;
use crate::vault::VaultState;

use anyhow::Context;
use core_ipc::{BusClient, Message};
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// Time-bounded cache of recently-seen replication envelope fingerprints.
/// Prevents replay amplification within the 5-minute timestamp acceptance
/// window. Without this, an attacker who captures a valid envelope can
/// replay it repeatedly, forcing the receiver to perform ECDH + HKDF +
/// ChaCha20 decryption on each replay before `INSERT OR IGNORE` dedup
/// catches it at the database layer.
///
/// Key: `(batch_hash_hex, nonce_b64)` — uniquely identifies an envelope
/// because each seal uses a fresh 12-byte random nonce.
/// Value: wall-clock timestamp when first seen (for expiration).
static SEEN_ENVELOPES: Mutex<Option<HashMap<(String, String), u64>>> = Mutex::new(None);

/// How long to retain seen envelope fingerprints. Matches the timestamp
/// acceptance window (300s) plus a 60s grace period for clock skew.
const ENVELOPE_CACHE_TTL_SECS: u64 = 360;

/// Maximum cache entries before forced eviction sweep.
const ENVELOPE_CACHE_MAX_SIZE: usize = 10_000;

/// Check if an envelope with this `(batch_hash, nonce)` pair has been seen
/// before. Returns `true` if this is a replay (already seen). Inserts the
/// pair on first encounter.
fn is_envelope_replay(batch_hash_hex: &str, nonce_b64: &str) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut guard = SEEN_ENVELOPES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let cache = guard.get_or_insert_with(HashMap::new);

    let key = (batch_hash_hex.to_string(), nonce_b64.to_string());

    if cache.contains_key(&key) {
        return true;
    }

    // Periodic eviction: when the cache is full, sweep stale entries.
    if cache.len() >= ENVELOPE_CACHE_MAX_SIZE {
        cache.retain(|_, ts| now.saturating_sub(*ts) < ENVELOPE_CACHE_TTL_SECS);
    }

    cache.insert(key, now);
    false
}

/// Grouped context for `handle_message` to avoid parameter explosion.
pub struct MessageContext<'a> {
    pub client: &'a mut BusClient,
    pub vault_state: &'a mut VaultState,
    pub config_dir: &'a Path,
    pub default_profile: &'a TrustProfileName,
    pub daemon_id: DaemonId,
    pub rate_limiter: &'a mut SecretRateLimiter,
    pub config: &'a core_config::Config,
}

/// Handle a single inbound IPC message. Returns false if the daemon should exit.
///
/// Dual audit strategy for secret operations:
/// 1. tracing (always local, journal-based) -- structured logs for each operation.
/// 2. IPC event (SecretOperationAudit, fire-and-forget to daemon-profile) -- persisted
///    in the hash-chained audit log by daemon-profile. Best-effort: delivery failure
///    must not block or fail secret operations.
///
/// Both paths are required. Do not remove one assuming the other is sufficient.
pub async fn handle_message(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
) -> anyhow::Result<bool> {
    let response_event = match &msg.payload {
        // Daemon announcements — verified identity comes from msg.verified_sender_name
        // stamped by the bus server.
        EventKind::DaemonStarted { .. } => None,

        // -- Unlock (per-profile) --
        EventKind::UnlockRequest { password, profile } => {
            return match unlock::handle_unlock_request(msg, ctx, password, profile).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- SSH-agent unlock (pre-derived master key) --
        EventKind::SshUnlockRequest {
            master_key,
            profile,
            ssh_fingerprint,
        } => {
            return match unlock::handle_ssh_unlock(msg, ctx, master_key, profile, ssh_fingerprint)
                .await
            {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Multi-factor: submit a single factor --
        EventKind::FactorSubmit {
            factor_id,
            key_material,
            profile,
            audit_metadata,
        } => {
            return match unlock::handle_factor_submit(
                msg,
                ctx,
                factor_id,
                key_material,
                profile,
                audit_metadata,
            )
            .await
            {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Multi-factor: query vault auth requirements --
        EventKind::VaultAuthQuery { profile } => unlock::handle_vault_auth_query(ctx, profile),

        // -- Lock (per-profile or all) --
        EventKind::LockRequest { profile } => {
            let event = unlock::handle_lock_request(msg, ctx, profile).await;
            match event {
                Some(ev) => {
                    return handle_post_dispatch(ctx, msg, ev).await;
                }
                None => return Ok(true),
            }
        }

        // StatusRequest is handled exclusively by daemon-profile, which queries
        // daemon-secrets via SecretsStateRequest for authoritative state.
        EventKind::StatusRequest => None,

        // -- Secret Get (profile-scoped) --
        EventKind::SecretGet { profile, key } => {
            return match crud::handle_secret_get(msg, ctx, profile, key).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Secret Set (profile-scoped) --
        EventKind::SecretSet {
            profile,
            key,
            value,
        } => {
            return match crud::handle_secret_set(msg, ctx, profile, key, value).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Secret Delete (profile-scoped) --
        EventKind::SecretDelete { profile, key } => {
            return match crud::handle_secret_delete(msg, ctx, profile, key).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Secret List (profile-scoped) --
        EventKind::SecretList { profile } => {
            return match crud::handle_secret_list(msg, ctx, profile).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Profile Activate (authorize + open vault) --
        EventKind::ProfileActivate { profile_name, .. } => {
            return match crud::handle_profile_activate(msg, ctx, profile_name).await {
                Ok(Some(event)) => handle_post_dispatch(ctx, msg, event).await,
                Ok(None) => Ok(true),
                Err(e) => Err(e),
            };
        }

        // -- Profile Deactivate (deauthorize, flush JIT, close vault) --
        EventKind::ProfileDeactivate { profile_name, .. } => {
            crud::handle_profile_deactivate(msg, ctx, profile_name).await
        }

        // -- State reconciliation: daemon-profile queries authoritative state --
        EventKind::SecretsStateRequest => crud::handle_secrets_state_request(ctx),

        // -- Network Identity --
        EventKind::NetworkIdentityRequest => {
            return match crate::network_identity::handle_network_identity_request(
                ctx.vault_state,
                ctx.default_profile,
            )
            .await
            {
                Some(event) => handle_post_dispatch(ctx, msg, event).await,
                None => Ok(true),
            };
        }

        // -- Vault Replication --
        EventKind::VaultLogEntryReceived { entry_json, .. /* peer_installation_id unused */ } => {
            // All received entries MUST be re-encrypted envelopes. Plaintext
            // entries are rejected — accepting them would bypass per-destination
            // confidentiality and allow IPC-level injection attacks.
            let plaintext_json = match decrypt_reencrypted_entry(entry_json) {
                Ok(json) => json,
                Err(e) => {
                    tracing::warn!(
                        rejection_reason = %e.reason,
                        entry_prefix = %e.entry_prefix,
                        "rejected vault log entry — not a valid re-encrypted envelope"
                    );
                    let _ = ctx.client.publish(
                        EventKind::SecretOperationAudit {
                            action: "replication_entry_rejected".into(),
                            profile: ctx.default_profile.clone(),
                            key: None,
                            requester: ctx.daemon_id,
                            requester_name: Some("daemon-secrets".into()),
                            outcome: format!("{} | prefix: {}", e.reason, e.entry_prefix),
                        },
                        SecurityLevel::Internal,
                    ).await;
                    return Ok(true);
                }
            };

            // The decrypted plaintext is the enriched batch from the sender's
            // pull response: [{entry: {wire}, value_b64: "..."}, ...].
            // Process each entry: HWM check → strip value → insert metadata
            // → apply value to vault (or defer).
            process_received_batch(&plaintext_json, ctx).await;
            None
        }
        EventKind::VaultReplicationPullRequest {
            profile_name,
            peer_id,
            since_watermark_json,
            max_entries,
        } => {
            return match build_pull_response(ctx, profile_name, peer_id, since_watermark_json.as_deref(), *max_entries).await {
                Some(event) => handle_post_dispatch(ctx, msg, event).await,
                None => Ok(true),
            };
        }

        // -- Replication pull progress update from daemon-network --
        EventKind::ReplicationPullProgressUpdate {
            peer_id,
            profile_name,
            last_hlc_json,
        } => {
            // S-05: Only accept from daemon-network at Internal security level.
            // An unauthenticated sender could advance pull_progress to trigger
            // premature compaction, causing data loss for legitimate peers.
            // Both checks are required: verified_sender_name confirms the Noise IK
            // identity, security_level confirms the bus server's clearance grant.
            if msg.verified_sender_name.as_deref() != Some("daemon-network")
                || msg.security_level < SecurityLevel::Internal
            {
                tracing::warn!(
                    audit = "security",
                    sender = ?msg.verified_sender_name,
                    security_level = ?msg.security_level,
                    "rejecting pull progress update from unauthorized sender"
                );
                return Ok(true);
            }
            if let Some(log) = crate::crud::vault_log_ref() {
                let v: serde_json::Value = serde_json::from_str(last_hlc_json)
                    .unwrap_or_default();
                let ws = v["wall_secs"].as_i64().unwrap_or(0);
                let ctr = v["counter"].as_i64().unwrap_or(0);
                if let Err(e) = log.update_pull_progress(peer_id, profile_name, ws, ctr) {
                    tracing::warn!(error = %e, "failed to update pull progress");
                }
            }
            None
        }

        // -- Ignore other events --
        _ => None,
    };

    if let Some(event) = response_event {
        return handle_post_dispatch(ctx, msg, event).await;
    }

    Ok(true)
}

/// Post-dispatch: broadcast lock state changes, then send correlated response.
async fn handle_post_dispatch(
    ctx: &mut MessageContext<'_>,
    msg: &Message<EventKind>,
    event: EventKind,
) -> anyhow::Result<bool> {
    // Broadcast lock state changes BEFORE the correlated unicast response.
    // This ensures daemon-profile sees the state change even if a crash occurs
    // between the broadcast and the CLI response.
    let broadcast = match &event {
        EventKind::UnlockResponse { success, profile } => Some(EventKind::UnlockResponse {
            success: *success,
            profile: profile.clone(),
        }),
        EventKind::LockResponse {
            success,
            profiles_locked,
        } => Some(EventKind::LockResponse {
            success: *success,
            profiles_locked: profiles_locked.clone(),
        }),
        _ => None,
    };

    if let Some(notify) = broadcast
        && let Err(e) = ctx.client.publish(notify, SecurityLevel::Internal).await
    {
        tracing::error!(
            audit = "security",
            error = %e,
            "lock/unlock broadcast failed — daemon-profile may have stale state"
        );
    }

    send_response(ctx.client, msg, event, ctx.daemon_id).await?;

    Ok(true)
}

/// Send a correlated response and return `Ok(None)` for use in handler
/// functions that return `Result<Option<EventKind>>`. This is the early-return
/// path: the response is sent directly and the dispatch layer has nothing to do.
pub async fn send_response_early(
    client: &mut BusClient,
    request: &Message<EventKind>,
    response_event: EventKind,
    daemon_id: DaemonId,
) -> anyhow::Result<Option<EventKind>> {
    send_response(client, request, response_event, daemon_id).await?;
    Ok(None)
}

/// Build a `VaultReplicationPullResponse` with secret values attached.
///
/// For each `set` entry in the log, reads the current value from the vault
/// and includes it as `value_b64` in the response JSON. Delete entries have
/// no value. Secret values are read at query time — they are never stored
/// in vault_log.db (F-02 invariant).
///
/// Value size is capped at 64KB per entry (M-05).
///
/// # Value hash binding (C-02 resolved)
///
/// Each `set` entry's signed payload includes `value_hash` (BLAKE3 of the
/// secret value at write time). The sender verifies that the current vault
/// value matches `value_hash` before attaching it to the response. If the
/// value has changed since the entry was logged (key overwritten), the value
/// is omitted — the entry is stale metadata. The receiver verifies
/// `BLAKE3(received_value) == signed value_hash` before applying. Mismatch
/// is rejected with an audit log entry.
///
/// This means entries for overwritten keys automatically become value-less
/// in pull responses. The receiver defers them, and the next pull brings
/// the newer entry with the correct value+hash pair. LWW convergence is
/// maintained with cryptographic value-binding.
///
/// # High-churn key limitation (S-04)
///
/// Keys that are overwritten faster than the pull cadence (default 60s)
/// will produce perpetual value_hash mismatches — each pull races with an
/// overwrite. The receiver defers with exponential backoff (30s → 1h).
/// Convergence occurs only when the key stabilizes for at least one pull
/// interval. This is inherent to the current-value-attachment design.
async fn build_pull_response(
    ctx: &mut MessageContext<'_>,
    profile_name_str: &str,
    peer_id: &str,
    since_watermark_json: Option<&str>,
    max_entries: u32,
) -> Option<EventKind> {
    use base64::Engine;

    let log = crate::crud::vault_log_ref()?;

    let result = match log.query_entries_since(profile_name_str, since_watermark_json, max_entries) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "vault log query failed");
            return None;
        }
    };

    // Parse entries to attach values for `set` operations.
    let entries: Vec<serde_json::Value> = match serde_json::from_str(&result.entries_json) {
        Ok(e) => e,
        Err(_) => return None,
    };

    let profile_name = match core_types::TrustProfileName::try_from(profile_name_str) {
        Ok(p) => p,
        Err(_) => return None,
    };

    let mut enriched = Vec::with_capacity(entries.len());
    let b64 = base64::engine::general_purpose::STANDARD;
    const MAX_VALUE_BYTES: usize = 64 * 1024;

    for entry in &entries {
        let mut obj = serde_json::json!({"entry": entry});

        if entry["operation_type"].as_str() == Some("set")
            && let Some(key) = entry["operation"]["key"].as_str()
            && let Ok(vault) = ctx.vault_state.vault_for(&profile_name).await
            && let Ok(value) = vault.resolve(key).await
        {
            // SAFETY (H1-NEW): The vault value is read ONCE into `value` via
            // vault.resolve(). Both the hash comparison and the base64 encoding
            // operate on the same in-memory snapshot (`val_bytes`). There is no
            // TOCTOU — the value cannot change between the hash check and the
            // encoding because they operate on the same borrowed slice. If the
            // key is overwritten concurrently, the receiver independently
            // verifies BLAKE3(received_value) == signed value_hash and rejects.
            let val_bytes = value.as_bytes();
            let current_hash = hex::encode(blake3::hash(val_bytes).as_bytes());
            let signed_hash = entry["operation"]["value_hash"].as_str().unwrap_or("");
            if current_hash != signed_hash {
                tracing::debug!(
                    key, signed_hash, current_hash,
                    "value_hash mismatch — key overwritten since entry was logged, omitting stale value"
                );
            } else if val_bytes.len() > MAX_VALUE_BYTES {
                tracing::warn!(key, len = val_bytes.len(), "secret value exceeds 64KB cap, omitting from replication");
            } else {
                obj["value_b64"] = serde_json::Value::String(b64.encode(val_bytes));
            }
        }

        enriched.push(obj);
    }

    let entries_json = serde_json::to_string(&enriched).unwrap_or_else(|_| "[]".into());

    Some(EventKind::VaultReplicationPullResponse {
        profile_name: profile_name_str.to_string(),
        peer_id: peer_id.to_string(),
        entries_json,
        has_more: false,
        last_hlc_json: result.last_hlc_json,
    })
}

/// Decryption failure context for forensic logging.
struct ReencryptionError {
    reason: &'static str,
    /// Truncated entry data for forensic correlation (first 128 chars, no secrets).
    entry_prefix: String,
}

impl std::fmt::Display for ReencryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

/// Decrypt a re-encrypted vault log entry. Fail-closed: rejects anything
/// that is not a valid re-encrypted envelope.
///
/// Re-encrypted entries arrive as a JSON envelope:
/// ```json
/// {"reencrypted": true, "ephemeral_pubkey": "<b64>", "nonce": "<b64>",
///  "ciphertext": "<b64>", "batch_hash": "<hex>"}
/// ```
///
/// Returns `Ok(plaintext_json)` on successful decryption.
/// Returns `Err(ReencryptionError)` for any failure — the caller MUST reject the entry.
fn decrypt_reencrypted_entry(entry_data: &str) -> Result<String, ReencryptionError> {
    let entry_prefix: String = entry_data.chars().take(128).collect();
    let err = |reason: &'static str| ReencryptionError {
        reason,
        entry_prefix: entry_prefix.clone(),
    };

    // M-05: reject oversized envelopes before parsing.
    const MAX_ENVELOPE_BYTES: usize = 256 * 1024; // 256KB — generous for JSON + base64 overhead
    if entry_data.len() > MAX_ENVELOPE_BYTES {
        return Err(err("envelope too large — rejected before parsing"));
    }

    let v: serde_json::Value = serde_json::from_str(entry_data)
        .map_err(|_| err("entry is not valid JSON"))?;

    if v["reencrypted"].as_bool() != Some(true) {
        return Err(err("entry missing reencrypted:true — plaintext entries rejected"));
    }

    // Replay protection: reject envelopes older than 5 minutes or from the future.
    const MAX_AGE_SECS: u64 = 300;
    const MAX_FUTURE_SECS: u64 = 60;
    let ts = v["timestamp_secs"].as_u64().ok_or_else(|| err("missing timestamp_secs"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(ts) > MAX_AGE_SECS {
        return Err(err("envelope too old — possible replay (>5 min)"));
    }
    if ts.saturating_sub(now) > MAX_FUTURE_SECS {
        return Err(err("envelope from the future — clock skew or replay"));
    }

    let session_id = v["session_id"].as_str().ok_or_else(|| err("missing session_id"))?;

    // Replay dedup: check the (batch_hash, nonce) fingerprint BEFORE the
    // expensive ECDH/HKDF/ChaCha decryption. Each legitimate envelope has a
    // fresh random 12-byte nonce, so the (hash, nonce) pair is unique. An
    // attacker replaying a captured envelope will hit this cache and be
    // rejected at near-zero cost instead of forcing a full AEAD cycle.
    let batch_hash_hex = v["batch_hash"].as_str().ok_or_else(|| err("missing batch_hash"))?;
    let nonce_b64 = v["nonce"].as_str().ok_or_else(|| err("missing nonce"))?;
    if is_envelope_replay(batch_hash_hex, nonce_b64) {
        return Err(err("duplicate envelope — replay rejected before decryption"));
    }

    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let eph_pubkey_bytes = b64.decode(
        v["ephemeral_pubkey"].as_str().ok_or_else(|| err("missing ephemeral_pubkey"))?
    ).map_err(|_| err("invalid base64 in ephemeral_pubkey"))?;
    // nonce_b64 and batch_hash_hex already extracted above for replay check.
    let nonce_bytes = b64.decode(nonce_b64)
        .map_err(|_| err("invalid base64 in nonce"))?;
    let ciphertext = b64.decode(
        v["ciphertext"].as_str().ok_or_else(|| err("missing ciphertext"))?
    ).map_err(|_| err("invalid base64 in ciphertext"))?;
    let batch_hash = hex::decode(batch_hash_hex)
        .map_err(|_| err("invalid hex in batch_hash"))?;

    let eph_pubkey: [u8; 32] = eph_pubkey_bytes.try_into()
        .map_err(|_| err("ephemeral_pubkey wrong length"))?;
    let nonce: [u8; 12] = nonce_bytes.try_into()
        .map_err(|_| err("nonce wrong length"))?;

    // Derive decryption key inside the closure so the private key never
    // leaves the RwLock scope. The derived key (not the private key) is
    // returned for AEAD open.
    let dec_key: [u8; 32] = crate::crud::with_network_private_key(|priv_key| {
        let private_secure = core_crypto::SecureBytes::from_slice(priv_key);
        let shared = core_crypto::network::x25519_dh(&private_secure, &eph_pubkey)?;
        let dec_keys = core_crypto::network::hkdf_blake2b(
            shared.as_bytes(),
            core_crypto::network::REPLICATION_HKDF_CONTEXT,
            1,
        );
        dec_keys[0].as_bytes().try_into()
            .map_err(|_| core_types::Error::Crypto("HKDF output wrong length".into()))
    })
    .ok_or_else(|| err("network private key not available — vault locked"))?
    .map_err(|_| err("ECDH/HKDF failed"))?;

    // Reconstruct AAD using the same shared function as the sender.
    let aad = core_crypto::network::replication_envelope_aad(&batch_hash, ts, session_id);

    let plaintext = core_crypto::network::chacha20_open(
        &dec_key, &nonce, &aad, &ciphertext,
    ).map_err(|_| err("AEAD decryption failed — wrong key or tampered ciphertext"))?;

    // L-02: bound decrypted plaintext size to prevent OOM from large batches.
    const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024; // 1MB
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(err("decrypted plaintext exceeds 1MB limit"));
    }

    String::from_utf8(plaintext.as_bytes().to_vec())
        .map_err(|_| err("decrypted plaintext is not valid UTF-8"))
}

/// Process a received batch of enriched entries from a peer.
///
/// The batch is a JSON array of `{"entry": {wire_format}, "value_b64": "..."}`.
/// For each entry: HWM check → strip value → insert metadata-only into vault_log
/// → apply value to vault (or defer if profile not active).
///
/// Secret values are NEVER stored in vault_log.db (F-02 invariant). They travel
/// in-memory from decryption to vault application.

async fn process_received_batch(batch_json: &str, ctx: &mut MessageContext<'_>) {
    use base64::Engine;
    use core_secrets::SecretsStore as _;

    let Some(log) = crate::crud::vault_log_ref() else {
        return;
    };

    let items: Vec<serde_json::Value> = match serde_json::from_str(batch_json) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse received batch JSON");
            return;
        }
    };

    let b64 = base64::engine::general_purpose::STANDARD;

    for item in &items {
        let entry = &item["entry"];
        let entry_str = serde_json::to_string(entry).unwrap_or_default();

        // S-02/H-02: SIGNATURE VERIFICATION FIRST. All field-content decisions
        // must happen AFTER the entry is proven authentic. This prevents:
        // - DoS via forged entries that pass HWM but fail signature
        // - Side-channel probing of HWM state via untrusted author fields
        // - Content-based rejections on unsigned data
        match crate::vault_log::VaultLog::validate_entry_structure(&entry_str) {
            Ok(()) => {}
            Err(crate::vault_log::VaultLogError::RejectedEntry(reason)) => {
                // Authenticated peer attempted forbidden content — loud audit.
                tracing::warn!(
                    audit = "security",
                    reason,
                    author = entry["author_installation_uuid"].as_str().unwrap_or(""),
                    "authenticated peer attempted forbidden content — possible compromise"
                );
                continue;
            }
            Err(e) => {
                tracing::debug!(error = %e, "entry failed validation, dropping");
                continue;
            }
        }

        // Now we trust the fields — signature binds them. The profile_id
        // is part of the signed payload, so a relay cannot splice entries
        // from a different profile without breaking the signature (M-01).
        let author = entry["author_installation_uuid"].as_str().unwrap_or("");
        let profile_id = entry["profile_id"].as_str().unwrap_or("");
        let wall_secs = entry["timestamp"]["wall_secs"].as_i64().unwrap_or(0);
        let counter = entry["timestamp"]["counter"].as_i64().unwrap_or(0);

        // HWM replay check — only after signature verification.
        match log.check_hwm(author, profile_id, wall_secs, counter) {
            Ok(true) => {}
            Ok(false) => {
                tracing::debug!(author, profile_id, wall_secs, counter, "entry rejected by HWM — replay or stale");
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "HWM check failed");
                continue;
            }
        }

        // Content checks — safe to read fields since entry is authenticated.
        let op_type = entry["operation_type"].as_str().unwrap_or("");
        let key = entry["operation"]["key"].as_str().unwrap_or("");

        // C-05: system keys and invalid keys rejected BEFORE insert.
        if key.starts_with('_') || (!key.is_empty() && core_types::validate_secret_key(key).is_err()) {
            tracing::debug!(key, "entry rejected pre-insert: system key or invalid key name");
            continue;
        }

        let profile = match core_types::TrustProfileName::try_from(profile_id) {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!(profile_id, "entry rejected pre-insert: invalid profile name");
                continue;
            }
        };

        // Insert metadata-only entry (no value) into vault_log.db.
        // validate_entry_structure already passed — insert_received_entry
        // will re-validate (belt-and-suspenders) but won't fail on structure.
        if let Err(e) = log.insert_received_entry(&entry_str) {
            tracing::warn!(error = %e, "failed to store received vault log entry");
            continue;
        }

        let entry_id = entry["id"].as_str().unwrap_or("");

        match op_type {
            "set" => {
                // Decode the value from the batch item (not from entry — F-02).
                let value_bytes = match item["value_b64"].as_str() {
                    Some(b64_str) => match b64.decode(b64_str) {
                        Ok(v) if v.len() <= 64 * 1024 => {
                            // Verify value_hash: the signed entry binds a BLAKE3
                            // hash of the value at write time. If the received value
                            // doesn't match, either the sender attached a stale value
                            // or the data was tampered. Reject.
                            let received_hash = hex::encode(blake3::hash(&v).as_bytes());
                            let signed_hash = entry["operation"]["value_hash"].as_str().unwrap_or("");

                            // H-06: set operations MUST have a value_hash.
                            // Empty value_hash on a set is invalid — reject.
                            if signed_hash.is_empty() {
                                tracing::warn!(entry = entry_id, "set entry missing value_hash, rejecting");
                                let _ = log.mark_applied(entry_id);
                                continue;
                            }

                            // S-03: Don't advance HWM on hash mismatch. The
                            // mismatch could be transient (key overwritten between
                            // pull-prepare and pull-deliver). Defer for retry —
                            // the next pull may bring a fresh entry with correct hash.
                            if received_hash != signed_hash {
                                tracing::warn!(
                                    entry = entry_id,
                                    signed_hash,
                                    received_hash,
                                    "value_hash mismatch — deferring for retry"
                                );
                                let _ = log.defer_entry_with_backoff(entry_id);
                                continue;
                            }
                            v
                        }
                        Ok(v) => {
                            tracing::warn!(entry = entry_id, len = v.len(), "value exceeds 64KB cap");
                            let _ = log.mark_applied(entry_id);
                            continue;
                        }
                        Err(_) => {
                            tracing::warn!(entry = entry_id, "invalid base64 in value_b64");
                            let _ = log.mark_applied(entry_id);
                            continue;
                        }
                    },
                    None => {
                        // No value in batch — sender couldn't read it (value_hash
                        // mismatch on their end, or vault locked). Defer.
                        let _ = log.defer_entry_with_backoff(entry_id);
                        tracing::debug!(entry = entry_id, key, "set entry missing value, deferred");
                        continue;
                    }
                };

                // Apply to vault if profile is active.
                //
                // TRUST MODEL (H3-NEW): Replicated entries bypass the local
                // per-daemon ACL (check_secret_access). This is by design —
                // the ACL system gates which LOCAL daemons can read which keys,
                // not which REMOTE installations can write. The security boundary
                // for replication is the TOFU pin check in daemon-network: only
                // Pinned/Bootstrap/Endorsed peers can deliver entries. An
                // Unpinned or Revoked peer's frames are dropped at the transport
                // layer before reaching daemon-secrets. Additionally, every
                // entry is Ed25519-signed and value-hash-bound, so a relay
                // cannot inject or modify entries without detection.
                match ctx.vault_state.vault_for(&profile).await {
                    Ok(vault) => {
                        match vault.store().set(key, &value_bytes).await {
                            Ok(()) => {
                                let _ = log.mark_applied(entry_id);
                                let _ = log.update_replay_hwm(author, profile_id, wall_secs, counter);
                                tracing::debug!(entry = entry_id, key, profile = profile_id, "applied set");
                            }
                            Err(e) => {
                                tracing::warn!(entry = entry_id, error = %e, "failed to apply set");
                            }
                        }
                    }
                    Err(_) => {
                        // Profile not active — defer with retry.
                        let _ = log.defer_entry_with_backoff(entry_id);
                        tracing::debug!(entry = entry_id, profile = profile_id, "profile not active, deferred set");
                    }
                }
            }
            "delete" => {
                match ctx.vault_state.vault_for(&profile).await {
                    Ok(vault) => {
                        match vault.store().delete(key).await {
                            Ok(()) | Err(core_types::Error::NotFound(_)) => {
                                let _ = log.mark_applied(entry_id);
                                let _ = log.update_replay_hwm(author, profile_id, wall_secs, counter);
                                tracing::debug!(entry = entry_id, key, profile = profile_id, "applied delete");
                            }
                            Err(e) => {
                                tracing::warn!(entry = entry_id, error = %e, "failed to apply delete");
                            }
                        }
                    }
                    Err(_) => {
                        let _ = log.defer_entry_with_backoff(entry_id);
                        tracing::debug!(entry = entry_id, profile = profile_id, "profile not active, deferred delete");
                    }
                }
            }
            other => {
                tracing::debug!(entry = entry_id, op = other, "unsupported operation type, marking applied");
                let _ = log.mark_applied(entry_id);
            }
        }
    }
}

/// Apply deferred vault log entries (periodic sweep).
///
/// Re-processes entries that were previously deferred because the profile
/// wasn't active. Only processes `delete` operations from the DB — `set`
/// operations that were deferred without values will be re-fetched on
/// the next periodic pull (their `deferred_until` expires, but without
/// a value they'll be deferred again until the next pull brings the value).
pub async fn apply_deferred_entries(ctx: &mut MessageContext<'_>) {
    use core_secrets::SecretsStore as _;

    let Some(log) = crate::crud::vault_log_ref() else {
        return;
    };

    let entries = match log.unapplied_entries(100) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "failed to query unapplied entries");
            return;
        }
    };

    if entries.is_empty() {
        return;
    }

    for entry in &entries {
        // M-01: Both local writes (write_local_entry) and received entries
        // (insert_received_entry with normalized operation_json) store the
        // same format: {"op","key","value_hash"}. Single parse path.
        let op: serde_json::Value = match serde_json::from_str(&entry.operation_json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(entry = %entry.id, error = %e, "malformed operation JSON, skipping");
                let _ = log.mark_applied(&entry.id);
                continue;
            }
        };

        let key = op["key"].as_str();
        let Some(key) = key else {
            let _ = log.mark_applied(&entry.id);
            continue;
        };

        if key.starts_with('_') || core_types::validate_secret_key(key).is_err() {
            let _ = log.mark_applied(&entry.id);
            continue;
        }

        let profile = match core_types::TrustProfileName::try_from(entry.profile_id.as_str()) {
            Ok(p) => p,
            Err(_) => {
                let _ = log.mark_applied(&entry.id);
                continue;
            }
        };

        match entry.operation_type.as_str() {
            "set" => {
                // C-04: Deferred sets have no value in the DB. Do NOT mark
                // applied or advance watermark — doing so permanently loses
                // the entry (watermark past it = never re-pulled). Leave the
                // entry unapplied so the next pull from the peer brings a
                // fresh batch with the value attached. process_received_batch
                // will apply it from memory via INSERT OR IGNORE (existing
                // entry) + in-memory value.
                //
                // The entry sits unapplied until the next successful pull
                // delivers the value. If the profile is permanently locked,
                // this entry occupies one slot indefinitely — acceptable.
                tracing::debug!(
                    entry = %entry.id, key,
                    "deferred set has no value in DB, leaving unapplied for next pull"
                );
                // No mark_applied, no update_watermark. Just skip.
            }
            "delete" => {
                match ctx.vault_state.vault_for(&profile).await {
                    Ok(vault) => {
                        match vault.store().delete(key).await {
                            Ok(()) | Err(core_types::Error::NotFound(_)) => {
                                let _ = log.mark_applied(&entry.id);
                                let _ = log.update_replay_hwm(
                                    &entry.author_installation_id,
                                    &entry.profile_id,
                                    entry.hlc_wall_secs,
                                    entry.hlc_counter,
                                );
                                tracing::debug!(entry = %entry.id, key, "deferred delete applied");
                            }
                            Err(e) => {
                                tracing::warn!(entry = %entry.id, error = %e, "failed to apply deferred delete");
                                let _ = log.defer_entry_with_backoff(&entry.id);
                            }
                        }
                    }
                    Err(_) => {
                        let _ = log.defer_entry_with_backoff(&entry.id);
                    }
                }
            }
            _ => {
                let _ = log.mark_applied(&entry.id);
            }
        }
    }
}

/// Send a correlated response to an inbound request.
pub async fn send_response(
    client: &mut BusClient,
    request: &Message<EventKind>,
    response_event: EventKind,
    daemon_id: DaemonId,
) -> anyhow::Result<bool> {
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);
    let response = Message::new(
        &msg_ctx,
        response_event,
        request.security_level,
        client.epoch(),
    )
    .with_correlation(request.msg_id);

    client
        .send(&response)
        .await
        .context("failed to send response")?;
    Ok(true)
}
