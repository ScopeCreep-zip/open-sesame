//! daemon-secrets: Secrets broker daemon.
//!
//! Manages encrypted per-profile secret vaults with JIT caching and IPC-based
//! request handling. Connects to the IPC bus as a client, accepts per-profile
//! `UnlockRequest` messages, then serves SecretGet/Set/Delete/List requests
//! against SQLCipher-backed stores keyed with BLAKE3-derived per-profile vault keys.
//!
//! # Startup sequence
//!
//! 1. Parse CLI, init logging, load config
//! 2. Apply Landlock + seccomp sandbox
//! 3. Connect to IPC bus as client
//! 4. Enter IPC event loop — vaults unlocked independently per profile
//! 5. Each `UnlockRequest` derives a per-profile master key via Argon2id
//! 6. Vaults opened lazily on first access after unlock + profile activation
//!
//! Multiple profiles may have open vaults concurrently. Each profile has its
//! own password, salt, and master key. Every secret RPC carries a `profile`
//! field identifying which vault to query.
//!
//! # Security constraints
//!
//! - Landlock: config dir (read), runtime dir (read/write), D-Bus socket (read/write)
//! - seccomp: restricted syscall set (no network, no ptrace)
//! - systemd: `PrivateNetwork=yes` (no network access)
//! - Per-profile password required to unlock each vault independently
//!
//! # Key hierarchy (ADR-SEC-002)
//!
//! ```text
//! Per-profile password → Argon2id(password, per-profile salt) → Master Key → BLAKE3 derive_key → vault key
//! ```

#[cfg(target_os = "linux")]
mod key_locker_linux;

mod acl;
mod rate_limit;

use acl::{
    audit_secret_access, check_secret_access, check_secret_list_access, check_secret_requester,
};
use rate_limit::SecretRateLimiter;

use anyhow::Context;
use clap::Parser;
use core_crypto::SecureBytes;
use core_ipc::{BusClient, Message};
use core_secrets::{JitDelivery, SecretsStore, SqlCipherStore};
use core_types::{
    DaemonId, EventKind, SecretDenialReason, SecurityLevel, SensitiveBytes, TrustProfileName,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;

/// PDS secrets broker daemon.
#[derive(Parser, Debug)]
#[command(name = "daemon-secrets", about = "PDS secrets broker")]
struct Cli {
    /// Config directory override.
    #[arg(long, env = "PDS_CONFIG_DIR")]
    config_dir: Option<PathBuf>,

    /// JIT cache TTL in seconds.
    #[arg(long, default_value = "300", env = "PDS_SECRET_TTL")]
    ttl: u64,

    /// Log format: "json" or "pretty".
    #[arg(long, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: String,
}

/// Runtime state for the secrets daemon.
///
/// Always present after daemon init (as an empty container). Individual profiles
/// are unlocked/locked independently — there is no global "locked" state.
struct VaultState {
    /// Per-profile master keys. Each derived independently from its own password+salt.
    /// Key: profile name. Value: master key (mlock'd, zeroize-on-drop).
    master_keys: HashMap<TrustProfileName, SecureBytes>,
    /// Trust profile name -> JitDelivery wrapping SqlCipherStore.
    /// Multiple vaults may be open concurrently.
    vaults: HashMap<TrustProfileName, JitDelivery<SqlCipherStore>>,
    /// Profiles explicitly authorized for secret access.
    /// This is the security boundary — vault_for() refuses profiles not in this set.
    /// Distinct from `vaults.keys()`: a profile may be authorized before its vault
    /// is lazily opened, or a vault may be open while deactivation is in progress.
    active_profiles: HashSet<TrustProfileName>,
    /// JIT TTL from CLI.
    ttl: Duration,
    /// Config directory for vault DB storage.
    config_dir: PathBuf,
}

impl VaultState {
    /// Get or lazily open a vault for the given trust profile.
    ///
    /// Refuses access if the profile is not in the active_profiles authorization set
    /// or if the profile's vault has not been unlocked.
    ///
    /// Vault opening uses `spawn_blocking` to avoid blocking the tokio event loop
    /// during synchronous SQLCipher I/O (PRAGMA key, schema migration).
    async fn vault_for(
        &mut self,
        profile: &TrustProfileName,
    ) -> core_types::Result<&JitDelivery<SqlCipherStore>> {
        if !self.active_profiles.contains(profile) {
            return Err(core_types::Error::Secrets(format!(
                "profile '{}' is not active — access denied",
                profile
            )));
        }
        let master_key = self.master_keys.get(profile).ok_or_else(|| {
            core_types::Error::Secrets(format!(
                "profile '{}' is not unlocked — run: sesame unlock --profile {}",
                profile, profile
            ))
        })?;
        if !self.vaults.contains_key(profile) {
            let vault_key = core_crypto::derive_vault_key(master_key.as_bytes(), profile);
            let db_path = self.config_dir.join("vaults").join(format!("{profile}.db"));

            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    core_types::Error::Secrets(format!(
                        "failed to create vault directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }

            // Wrap synchronous SQLCipher open in spawn_blocking to avoid blocking
            // the event loop during PRAGMA key + schema migration.
            let db_path_clone = db_path.clone();
            let store = tokio::task::spawn_blocking(move || {
                SqlCipherStore::open(&db_path_clone, &vault_key)
            })
            .await
            .map_err(|e| core_types::Error::Secrets(format!("spawn_blocking join error: {e}")))??;

            let jit = JitDelivery::new(store, self.ttl);
            self.vaults.insert(profile.clone(), jit);
            tracing::info!(profile = %profile, path = %db_path.display(), "vault opened");
        }
        Ok(self.vaults.get(profile).expect("just inserted"))
    }

    /// Authorize a profile for secret access. Must be called before vault_for().
    fn activate_profile(&mut self, profile: &TrustProfileName) {
        self.active_profiles.insert(profile.clone());
        tracing::info!(profile = %profile, "profile authorized for secret access");
    }

    /// Deactivate a trust profile: deauthorize, flush JIT cache, close vault.
    ///
    /// Idempotent: deactivating an already-inactive profile is not an error.
    /// Deauthorization (removing from active_profiles) is the security operation
    /// and happens FIRST — before vault close.
    async fn deactivate_profile(&mut self, profile: &TrustProfileName) {
        self.active_profiles.remove(profile);
        if let Some(vault) = self.vaults.remove(profile) {
            vault.flush().await;
            vault.store().pragma_rekey_clear();
            drop(vault);
            tracing::info!(profile = %profile, "vault deactivated and key material zeroized");
        }
    }

    /// Names of all profiles authorized for secret access.
    ///
    /// Returns the authorization set, NOT the set of open vaults.
    /// These can diverge: a profile may be authorized before its vault
    /// is lazily opened.
    fn active_profiles(&self) -> Vec<TrustProfileName> {
        self.active_profiles.iter().cloned().collect()
    }

    /// Get the per-profile IPC encryption key (ADR-SEC-006, defense-in-depth).
    ///
    /// Used to encrypt secret values before placing them on the IPC bus,
    /// providing per-field encryption on top of Noise transport encryption.
    /// Per-field IPC encryption (ADR-SEC-006, feature-gated).
    ///
    /// Defense-in-depth: AES-256-GCM per secret value on the IPC bus, layered
    /// on top of Noise IK transport encryption. Gated behind `ipc-field-encryption`
    /// feature because:
    /// - The Noise transport is already the security boundary (matching
    ///   ssh-agent, 1Password, Vault, gpg-agent precedent)
    /// - CLI clients lack the master key needed for per-field encryption
    /// - The per-field key derives from the same master key that transits
    ///   inside the Noise channel (not an independent trust root)
    ///
    /// Enable for research into daemon-to-daemon relay defense-in-depth.
    #[cfg(feature = "ipc-field-encryption")]
    fn ipc_encryption_key(
        &self,
        profile: &TrustProfileName,
    ) -> core_types::Result<core_crypto::EncryptionKey> {
        let master_key = self.master_keys.get(profile).ok_or_else(|| {
            core_types::Error::Secrets(format!(
                "profile '{}' not unlocked for IPC encryption",
                profile
            ))
        })?;
        let key_bytes = core_crypto::derive_ipc_encryption_key(master_key.as_bytes(), profile);
        let key_array: &[u8; 32] = key_bytes
            .as_bytes()
            .try_into()
            .map_err(|_| core_types::Error::Crypto("IPC encryption key is not 32 bytes".into()))?;
        core_crypto::EncryptionKey::from_bytes(key_array)
    }

    #[cfg(feature = "ipc-field-encryption")]
    fn encrypt_for_ipc(
        &self,
        profile: &TrustProfileName,
        plaintext: &[u8],
    ) -> core_types::Result<Vec<u8>> {
        let enc_key = self.ipc_encryption_key(profile)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| core_types::Error::Crypto(format!("nonce generation failed: {e}")))?;
        let ciphertext = enc_key.encrypt(&nonce, plaintext)?;
        let mut wire = Vec::with_capacity(12 + ciphertext.len());
        wire.extend_from_slice(&nonce);
        wire.extend(ciphertext);
        Ok(wire)
    }

    #[cfg(feature = "ipc-field-encryption")]
    fn decrypt_from_ipc(
        &self,
        profile: &TrustProfileName,
        wire: &[u8],
    ) -> core_types::Result<Vec<u8>> {
        if wire.len() < 12 {
            return Err(core_types::Error::Crypto(
                "IPC-encrypted value too short (missing nonce)".into(),
            ));
        }
        let nonce: [u8; 12] = wire[..12]
            .try_into()
            .map_err(|_| core_types::Error::Crypto("nonce extraction failed".into()))?;
        let ciphertext = &wire[12..];
        let enc_key = self.ipc_encryption_key(profile)?;
        let plaintext = enc_key.decrypt(&nonce, ciphertext)?;
        Ok(plaintext.as_bytes().to_vec())
    }
}

// Access audit, anomaly detection, rate limiting, and per-secret ACL
// implementations are extracted to `acl` and `rate_limit` modules.

/// Validate a secret key name (defense-in-depth).
/// Delegates to the canonical implementation in core-types.
fn validate_secret_key(key: &str) -> core_types::Result<()> {
    core_types::validate_secret_key(key)
}

/// Emit a secret operation audit event on the IPC bus for persistent logging
/// by daemon-profile. Fire-and-forget: audit event delivery failure must not
/// block or fail secret operations.
///
/// SECURITY: This function must NEVER receive or emit secret values.
/// Only metadata (action, profile, key name, requester, outcome).
async fn emit_audit_event(
    client: &BusClient,
    action: &str,
    profile: &TrustProfileName,
    key: Option<&str>,
    requester: DaemonId,
    requester_name: Option<&str>,
    outcome: &str,
) {
    let event = EventKind::SecretOperationAudit {
        action: action.to_owned(),
        profile: profile.clone(),
        key: key.map(ToOwned::to_owned),
        requester,
        requester_name: requester_name.map(ToOwned::to_owned),
        outcome: outcome.to_owned(),
    };
    if let Err(e) = client.publish(event, SecurityLevel::Internal).await {
        tracing::warn!(error = %e, action, "failed to emit secret audit event");
    }
}

/// Per-profile salt file path: `{config_dir}/vaults/{profile}.salt`
fn profile_salt_path(config_dir: &Path, profile: &TrustProfileName) -> PathBuf {
    config_dir.join("vaults").join(format!("{profile}.salt"))
}

/// Derive the master key from password + salt via Argon2id.
fn derive_master_key(password: &[u8], salt: &[u8; 16]) -> core_types::Result<SecureBytes> {
    core_crypto::derive_key_argon2(password, salt)
}

/// Generate a new per-profile salt and persist to disk.
fn generate_profile_salt(salt_path: &Path) -> core_types::Result<[u8; 16]> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|e| core_types::Error::Crypto(format!("getrandom failed: {e}")))?;
    if let Some(parent) = salt_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            core_types::Error::Config(format!("failed to create vault directory: {e}"))
        })?;
    }
    std::fs::write(salt_path, salt)
        .map_err(|e| core_types::Error::Config(format!("failed to write profile salt: {e}")))?;
    Ok(salt)
}

/// Load a salt file from disk.
fn load_salt(path: &Path) -> core_types::Result<[u8; 16]> {
    let salt_bytes = std::fs::read(path).map_err(|e| {
        core_types::Error::Config(format!("failed to read salt from {}: {e}", path.display()))
    })?;
    salt_bytes
        .try_into()
        .map_err(|_| core_types::Error::Config("salt file is not 16 bytes".into()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // -- Logging --
    init_logging(&cli.log_format)?;

    tracing::info!("daemon-secrets starting");

    // -- Process hardening --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    // -- Config --
    let mut config = core_config::load_config(None).context("failed to load config")?;
    tracing::debug!(?config, "config loaded");

    // Config hot-reload.
    // SECURITY: The live_config Arc<RwLock<Config>> is the authoritative config
    // state after hot-reload. The local `config` binding is refreshed on each
    // reload notification so ACL rules take effect immediately. Without this,
    // ACL changes in config.toml are silently ignored until daemon restart.
    let config_paths_for_watch = core_config::resolve_config_paths(None);
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let (_config_watcher, live_config) = core_config::ConfigWatcher::with_callback(
        &config_paths_for_watch,
        config.clone(),
        Some(Box::new(move || {
            let _ = reload_tx.blocking_send(());
        })),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let config_dir = core_config::config_dir();
    let default_profile: TrustProfileName = config.global.default_profile.clone();

    // -- IPC bus connection: read keypair BEFORE sandbox (keypair files need to be open) --
    let socket_path = core_ipc::socket_path().context("failed to resolve IPC socket path")?;
    tracing::info!(path = %socket_path.display(), "connecting to IPC bus");

    let daemon_id = DaemonId::new();
    let server_pub = core_ipc::noise::read_bus_public_key()
        .await
        .context("failed to read bus server public key")?;

    // Connect with keypair retry (daemon-profile may regenerate on crash-restart).
    // First attempt reads keypair; sandbox applied after successful read.
    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-secrets",
        daemon_id,
        &socket_path,
        &server_pub,
        5,
        Duration::from_millis(500),
    )
    .await
    .context("failed to connect to IPC bus")?;
    // ZeroizingKeypair: private key zeroized on drop (no manual zeroize needed).
    drop(_client_keypair);

    // -- Sandbox (Linux) -- applied AFTER keypair read, BEFORE IPC traffic.
    #[cfg(target_os = "linux")]
    apply_sandbox();

    tracing::info!("connected to IPC bus (Noise IK encrypted)");

    // -- Announce startup --
    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: env!("CARGO_PKG_VERSION").into(),
                capabilities: vec!["secrets".into(), "keylocker".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .context("failed to announce startup")?;

    // -- Platform readiness --
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-secrets ready (locked, awaiting UnlockRequest)");

    // -- Watchdog timer: half the WatchdogSec=30 interval --
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    // -- Main event loop --
    // VaultState is always present; individual profiles are unlocked/locked independently.
    let mut vault_state = VaultState {
        master_keys: HashMap::new(),
        vaults: HashMap::new(),
        active_profiles: HashSet::new(),
        ttl: Duration::from_secs(cli.ttl),
        config_dir: config_dir.clone(),
    };
    let mut rate_limiter = SecretRateLimiter::new();

    let mut watchdog_count: u64 = 0;
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                watchdog_count += 1;
                if watchdog_count <= 3 || watchdog_count.is_multiple_of(20) {
                    tracing::info!(watchdog_count, "watchdog tick");
                }
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }
            msg = client.recv() => {
                let Some(msg) = msg else {
                    tracing::error!("IPC bus disconnected — exiting with non-zero code for systemd restart");
                    // std::process::exit() skips destructors. Explicitly zeroize
                    // all open vault key material before exiting so the C-level
                    // SQLCipher key buffer is cleared even on crash-restart paths.
                    for (_profile, vault) in vault_state.vaults.drain() {
                        vault.store().pragma_rekey_clear();
                    }
                    std::process::exit(1);
                };

                // Skip self-published messages to prevent feedback loops.
                if msg.sender == daemon_id {
                    continue;
                }

                let mut ctx = MessageContext {
                    client: &mut client,
                    vault_state: &mut vault_state,
                    config_dir: &config_dir,
                    default_profile: &default_profile,
                    daemon_id,
                    rate_limiter: &mut rate_limiter,
                    config: &config,
                    socket_path: &socket_path,
                    server_pub: &server_pub,
                };
                match handle_message(&msg, &mut ctx).await {
                    Ok(should_continue) => {
                        if !should_continue {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "message handler failed");
                    }
                }
            }
            Some(()) = reload_rx.recv() => {
                // SECURITY: Re-read the live config so ACL rule changes take
                // effect immediately. Without this, check_secret_access() uses
                // the stale config from process startup.
                // NOTE: std::sync::RwLock (not tokio) — watcher holds write lock <1ms during
                // parse-and-swap, so this will not block the async runtime in practice.
                if let Ok(guard) = live_config.read() {
                    config = (*guard).clone();
                    tracing::info!("config reloaded (ACL rules refreshed)");
                } else {
                    tracing::error!("config reload: failed to acquire live_config read lock");
                }
                client.publish(
                    EventKind::ConfigReloaded {
                        daemon_id,
                        changed_keys: vec!["secrets".into()],
                    },
                    SecurityLevel::Internal,
                ).await.ok();
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received");
                break;
            }
            _ = sigterm() => {
                tracing::info!("SIGTERM received");
                break;
            }
        }
    }

    // Graceful shutdown: zeroize all master keys, close all open vaults, clear keyring.
    // SecureBytes zeroizes on drop. SqlCipherStore closes DB connections on drop.
    {
        let count = vault_state.vaults.len();
        let profile_names: Vec<TrustProfileName> =
            vault_state.master_keys.keys().cloned().collect();
        vault_state.active_profiles.clear();
        for (_profile, vault) in vault_state.vaults.drain() {
            vault.flush().await;
            vault.store().pragma_rekey_clear();
            drop(vault);
        }
        vault_state.master_keys.clear(); // Each SecureBytes zeroizes on drop.
        #[cfg(target_os = "linux")]
        keyring_delete_all(&profile_names).await;
        tracing::info!(
            vault_count = count,
            "all master keys zeroized, all vaults closed"
        );
    }

    client
        .publish(
            EventKind::DaemonStopped {
                daemon_id,
                reason: "shutdown".into(),
            },
            SecurityLevel::Internal,
        )
        .await
        .ok(); // Best-effort on shutdown.

    tracing::info!("daemon-secrets shutting down");
    Ok(())
}

/// Grouped context for `handle_message` to avoid parameter explosion.
struct MessageContext<'a> {
    client: &'a mut BusClient,
    vault_state: &'a mut VaultState,
    config_dir: &'a Path,
    default_profile: &'a TrustProfileName,
    daemon_id: DaemonId,
    rate_limiter: &'a mut SecretRateLimiter,
    config: &'a core_config::Config,
    socket_path: &'a Path,
    server_pub: &'a [u8; 32],
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
#[allow(clippy::too_many_lines)]
async fn handle_message(
    msg: &Message<EventKind>,
    ctx: &mut MessageContext<'_>,
) -> anyhow::Result<bool> {
    let response_event = match &msg.payload {
        // Daemon announcements — verified identity comes from msg.verified_sender_name
        // stamped by the bus server.
        EventKind::DaemonStarted { .. } => None,

        // Key rotation — reconnect with new keypair via shared handler.
        EventKind::KeyRotationPending {
            daemon_name,
            new_pubkey,
            grace_period_s,
        } if daemon_name == "daemon-secrets" => {
            tracing::info!(
                grace_period_s,
                "key rotation pending, will reconnect with new keypair"
            );
            match BusClient::handle_key_rotation(
                "daemon-secrets",
                ctx.daemon_id,
                ctx.socket_path,
                ctx.server_pub,
                new_pubkey,
                vec!["secrets".into(), "keylocker".into()],
                env!("CARGO_PKG_VERSION"),
            )
            .await
            {
                Ok(new_client) => {
                    *ctx.client = new_client;
                    tracing::info!("reconnected with rotated keypair");
                }
                Err(e) => tracing::error!(error = %e, "key rotation reconnect failed"),
            }
            None
        }

        // -- Unlock (per-profile) --
        EventKind::UnlockRequest { password, profile } => {
            let target = profile
                .clone()
                .unwrap_or_else(|| ctx.default_profile.clone());

            if ctx.vault_state.master_keys.contains_key(&target) {
                tracing::warn!(audit = "security", profile = %target, "unlock request for already-unlocked profile — rejected");
                audit_secret_access(
                    "unlock",
                    msg.sender,
                    &target,
                    None,
                    "rejected-already-unlocked",
                );
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::UnlockRejected {
                        reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
                        profile: Some(target),
                    },
                    ctx.daemon_id,
                )
                .await;
            }
            let outcome = match unlock_profile(password.as_bytes(), &target, ctx.config_dir).await {
                Ok(result) => {
                    // Store per-profile keyring entry BEFORE transferring ownership
                    // to the map — avoids retrieving from map and eliminates unwrap.
                    #[cfg(target_os = "linux")]
                    {
                        let salt_path = profile_salt_path(ctx.config_dir, &target);
                        if let Ok(salt_bytes) = std::fs::read(&salt_path) {
                            keyring_store_profile(
                                &result.master_key,
                                password.as_bytes(),
                                &salt_bytes,
                                &target,
                            )
                            .await;
                        }
                    }

                    ctx.vault_state
                        .master_keys
                        .insert(target.clone(), result.master_key);

                    // Cache verified store to avoid redundant SQLCipher open on ProfileActivate.
                    if let Some(store) = result.verified_store {
                        let jit = JitDelivery::new(store, ctx.vault_state.ttl);
                        ctx.vault_state.vaults.insert(target.clone(), jit);
                    }

                    tracing::info!(profile = %target, "vault unlocked");
                    "success"
                }
                Err(e) => {
                    tracing::error!(error = %e, profile = %target, "unlock failed");
                    "failed"
                }
            };
            audit_secret_access("unlock", msg.sender, &target, None, outcome);
            Some(EventKind::UnlockResponse {
                success: outcome == "success",
                profile: target,
            })
        }

        // -- SSH-agent unlock (pre-derived master key) --
        EventKind::SshUnlockRequest {
            master_key,
            profile,
            ssh_fingerprint,
        } => {
            let target = profile.clone();

            if ctx.vault_state.master_keys.contains_key(&target) {
                tracing::warn!(audit = "security", profile = %target, "SSH unlock request for already-unlocked profile — rejected");
                audit_secret_access(
                    "ssh-unlock",
                    msg.sender,
                    &target,
                    None,
                    "rejected-already-unlocked",
                );
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::UnlockRejected {
                        reason: core_types::UnlockRejectedReason::AlreadyUnlocked,
                        profile: Some(target),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // Convert SensitiveBytes to SecureBytes (copy into mlock'd memory).
            let secure_master_key = SecureBytes::new(master_key.as_bytes().to_vec());

            // Verify against existing vault DB if it exists.
            let vault_path = ctx.config_dir.join("vaults").join(format!("{target}.db"));
            let (success, verified_store) = if vault_path.exists() {
                let vault_key =
                    core_crypto::derive_vault_key(secure_master_key.as_bytes(), &target);
                let vp = vault_path;
                match tokio::task::spawn_blocking(move || SqlCipherStore::open(&vp, &vault_key))
                    .await
                {
                    Ok(Ok(store)) => {
                        tracing::info!(profile = %target, ssh_fingerprint = %ssh_fingerprint, "vault key verified via SSH");
                        (true, Some(store))
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, profile = %target, "SSH unlock vault key verification failed");
                        (false, None)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, profile = %target, "SSH unlock spawn_blocking failed");
                        (false, None)
                    }
                }
            } else {
                // No vault DB yet — accept the master key on faith.
                (true, None)
            };

            if success {
                ctx.vault_state
                    .master_keys
                    .insert(target.clone(), secure_master_key);
                if let Some(store) = verified_store {
                    let jit = JitDelivery::new(store, ctx.vault_state.ttl);
                    ctx.vault_state.vaults.insert(target.clone(), jit);
                }
                tracing::info!(profile = %target, ssh_fingerprint = %ssh_fingerprint, "vault unlocked via SSH");
            }

            audit_secret_access(
                "ssh-unlock",
                msg.sender,
                &target,
                None,
                if success { "success" } else { "failed" },
            );
            Some(EventKind::UnlockResponse {
                success,
                profile: target,
            })
        }

        // -- Lock (per-profile or all) --
        EventKind::LockRequest { profile } => {
            let profiles_locked: Vec<TrustProfileName> = match profile {
                Some(target) => {
                    // Lock single profile.
                    ctx.vault_state.active_profiles.remove(target);
                    if let Some(vault) = ctx.vault_state.vaults.remove(target) {
                        vault.flush().await;
                        vault.store().pragma_rekey_clear();
                        drop(vault);
                    }
                    ctx.vault_state.master_keys.remove(target); // zeroizes on drop
                    #[cfg(target_os = "linux")]
                    keyring_delete_profile(target).await;
                    tracing::info!(profile = %target, "vault locked, key material zeroized");
                    vec![target.clone()]
                }
                None => {
                    // Lock all profiles.
                    let locked: Vec<TrustProfileName> =
                        ctx.vault_state.master_keys.keys().cloned().collect();
                    ctx.vault_state.active_profiles.clear();
                    for (_profile, vault) in ctx.vault_state.vaults.drain() {
                        vault.flush().await;
                        vault.store().pragma_rekey_clear();
                        drop(vault);
                    }
                    ctx.vault_state.master_keys.clear(); // each SecureBytes zeroizes on drop
                    #[cfg(target_os = "linux")]
                    keyring_delete_all(&locked).await;
                    tracing::info!("all vaults locked, key material zeroized");
                    locked
                }
            };
            *ctx.rate_limiter = SecretRateLimiter::new();
            audit_secret_access("lock", msg.sender, "-", None, "success");
            Some(EventKind::LockResponse {
                success: true,
                profiles_locked,
            })
        }

        // StatusRequest is handled exclusively by daemon-profile, which queries
        // daemon-secrets via SecretsStateRequest for authoritative state.
        EventKind::StatusRequest => None,

        // -- Secret Get (profile-scoped) --
        // Check order: lock -> active profile -> identity -> rate limit -> ACL -> vault
        EventKind::SecretGet { profile, key } => {
            // 1. LOCK CHECK (cheapest, most restrictive — no timing/rate leaks when locked).
            let Some(state) = Some(&mut ctx.vault_state).filter(|s| !s.master_keys.is_empty())
            else {
                audit_secret_access("get", msg.sender, profile, Some(key), "denied-locked");
                emit_audit_event(
                    ctx.client,
                    "get",
                    profile,
                    Some(key),
                    msg.sender,
                    msg.verified_sender_name.as_deref(),
                    "denied-locked",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretGetResponse {
                        key: key.clone(),
                        value: SensitiveBytes::new(vec![]),
                        denial: Some(SecretDenialReason::Locked),
                    },
                    ctx.daemon_id,
                )
                .await;
            };

            // 2. ACTIVE PROFILE CHECK.
            if !state.active_profiles.contains(profile) {
                audit_secret_access(
                    "get",
                    msg.sender,
                    profile,
                    Some(key),
                    "denied-profile-not-active",
                );
                emit_audit_event(
                    ctx.client,
                    "get",
                    profile,
                    Some(key),
                    msg.sender,
                    msg.verified_sender_name.as_deref(),
                    "denied-profile-not-active",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretGetResponse {
                        key: key.clone(),
                        value: SensitiveBytes::new(vec![]),
                        denial: Some(SecretDenialReason::ProfileNotActive),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 3. IDENTITY CHECK (server-verified sender name).
            let requester_name = msg.verified_sender_name.as_deref();
            check_secret_requester(msg.sender, requester_name);

            // 4. RATE LIMIT CHECK.
            if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
                tracing::warn!(
                    audit = "rate-limit",
                    requester = %msg.sender,
                    profile = %profile,
                    key,
                    "secret request rate limit exceeded"
                );
                audit_secret_access("get", msg.sender, profile, Some(key), "rate-limited");
                emit_audit_event(
                    ctx.client,
                    "get",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "rate-limited",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretGetResponse {
                        key: key.clone(),
                        value: SensitiveBytes::new(vec![]),
                        denial: Some(SecretDenialReason::RateLimited),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 5. ACL CHECK (per-secret access control).
            if !check_secret_access(ctx.config, profile, requester_name, key) {
                tracing::warn!(
                    audit = "access-denied",
                    requester = %msg.sender,
                    daemon_name = requester_name.unwrap_or("unknown"),
                    profile = %profile,
                    key,
                    "secret access denied by per-profile ACL"
                );
                audit_secret_access("get", msg.sender, profile, Some(key), "denied-acl");
                emit_audit_event(
                    ctx.client,
                    "get",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "denied-acl",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretGetResponse {
                        key: key.clone(),
                        value: SensitiveBytes::new(vec![]),
                        denial: Some(SecretDenialReason::AccessDenied),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 5.5. KEY VALIDATION (defense-in-depth).
            if let Err(e) = validate_secret_key(key) {
                audit_secret_access("get", msg.sender, profile, Some(key), "denied-invalid-key");
                emit_audit_event(
                    ctx.client,
                    "get",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "denied-invalid-key",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretGetResponse {
                        key: key.clone(),
                        value: SensitiveBytes::new(vec![]),
                        denial: Some(SecretDenialReason::VaultError(e.to_string())),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 6. VAULT ACCESS.
            match state.vault_for(profile).await {
                Ok(vault) => match vault.resolve(key).await {
                    Ok(secret) => {
                        #[cfg(feature = "ipc-field-encryption")]
                        let (value, denial) = match state
                            .encrypt_for_ipc(profile, secret.as_bytes())
                        {
                            Ok(v) => (SensitiveBytes::new(v), None),
                            Err(e) => {
                                tracing::error!(profile = %profile, key, error = %e, "IPC encryption failed");
                                (
                                    SensitiveBytes::new(vec![]),
                                    Some(SecretDenialReason::VaultError(format!(
                                        "IPC encryption failed: {e}"
                                    ))),
                                )
                            }
                        };
                        #[cfg(not(feature = "ipc-field-encryption"))]
                        let (value, denial): (
                            SensitiveBytes,
                            Option<SecretDenialReason>,
                        ) = (SensitiveBytes::new(secret.as_bytes().to_vec()), None);

                        audit_secret_access("get", msg.sender, profile, Some(key), "success");
                        emit_audit_event(
                            ctx.client,
                            "get",
                            profile,
                            Some(key),
                            msg.sender,
                            requester_name,
                            "success",
                        )
                        .await;
                        Some(EventKind::SecretGetResponse {
                            key: key.clone(),
                            value,
                            denial,
                        })
                    }
                    Err(e) => {
                        tracing::warn!(profile = %profile, key, error = %e, "secret get failed");
                        audit_secret_access("get", msg.sender, profile, Some(key), "not-found");
                        emit_audit_event(
                            ctx.client,
                            "get",
                            profile,
                            Some(key),
                            msg.sender,
                            requester_name,
                            "not-found",
                        )
                        .await;
                        Some(EventKind::SecretGetResponse {
                            key: key.clone(),
                            value: SensitiveBytes::new(vec![]),
                            denial: Some(SecretDenialReason::NotFound),
                        })
                    }
                },
                Err(e) => {
                    tracing::error!(profile = %profile, error = %e, "vault access failed");
                    audit_secret_access("get", msg.sender, profile, Some(key), "vault-error");
                    emit_audit_event(
                        ctx.client,
                        "get",
                        profile,
                        Some(key),
                        msg.sender,
                        requester_name,
                        "vault-error",
                    )
                    .await;
                    Some(EventKind::SecretGetResponse {
                        key: key.clone(),
                        value: SensitiveBytes::new(vec![]),
                        denial: Some(SecretDenialReason::VaultError(e.to_string())),
                    })
                }
            }
        }

        // -- Secret Set (profile-scoped) --
        // Check order: lock -> active profile -> identity -> rate limit -> ACL -> vault
        EventKind::SecretSet {
            profile,
            key,
            value,
        } => {
            // 1. LOCK CHECK.
            let Some(state) = Some(&mut ctx.vault_state).filter(|s| !s.master_keys.is_empty())
            else {
                audit_secret_access("set", msg.sender, profile, Some(key), "denied-locked");
                emit_audit_event(
                    ctx.client,
                    "set",
                    profile,
                    Some(key),
                    msg.sender,
                    msg.verified_sender_name.as_deref(),
                    "denied-locked",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretSetResponse {
                        success: false,
                        denial: Some(SecretDenialReason::Locked),
                    },
                    ctx.daemon_id,
                )
                .await;
            };

            // 2. ACTIVE PROFILE CHECK.
            if !state.active_profiles.contains(profile) {
                audit_secret_access(
                    "set",
                    msg.sender,
                    profile,
                    Some(key),
                    "denied-profile-not-active",
                );
                emit_audit_event(
                    ctx.client,
                    "set",
                    profile,
                    Some(key),
                    msg.sender,
                    msg.verified_sender_name.as_deref(),
                    "denied-profile-not-active",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretSetResponse {
                        success: false,
                        denial: Some(SecretDenialReason::ProfileNotActive),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 3. IDENTITY CHECK.
            let requester_name = msg.verified_sender_name.as_deref();
            check_secret_requester(msg.sender, requester_name);

            // 4. RATE LIMIT CHECK.
            if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
                tracing::warn!(
                    audit = "rate-limit",
                    requester = %msg.sender,
                    profile = %profile,
                    key,
                    "secret request rate limit exceeded"
                );
                audit_secret_access("set", msg.sender, profile, Some(key), "rate-limited");
                emit_audit_event(
                    ctx.client,
                    "set",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "rate-limited",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretSetResponse {
                        success: false,
                        denial: Some(SecretDenialReason::RateLimited),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 5. ACL CHECK.
            if !check_secret_access(ctx.config, profile, requester_name, key) {
                tracing::warn!(
                    audit = "access-denied",
                    requester = %msg.sender,
                    daemon_name = requester_name.unwrap_or("unknown"),
                    profile = %profile,
                    key,
                    "secret access denied by per-profile ACL"
                );
                audit_secret_access("set", msg.sender, profile, Some(key), "denied-acl");
                emit_audit_event(
                    ctx.client,
                    "set",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "denied-acl",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretSetResponse {
                        success: false,
                        denial: Some(SecretDenialReason::AccessDenied),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 5.5. KEY VALIDATION (defense-in-depth).
            if let Err(e) = validate_secret_key(key) {
                audit_secret_access("set", msg.sender, profile, Some(key), "denied-invalid-key");
                emit_audit_event(
                    ctx.client,
                    "set",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "denied-invalid-key",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretSetResponse {
                        success: false,
                        denial: Some(SecretDenialReason::VaultError(e.to_string())),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 6. VAULT ACCESS (IPC field decryption runs here, after all gates pass).
            #[cfg(feature = "ipc-field-encryption")]
            let mut store_value = match state.decrypt_from_ipc(profile, value.as_bytes()) {
                Ok(pt) => pt,
                Err(e) => {
                    tracing::error!(profile = %profile, key, error = %e, "IPC decryption of secret value failed");
                    audit_secret_access("set", msg.sender, profile, Some(key), "decrypt-error");
                    return send_response(
                        ctx.client,
                        msg,
                        EventKind::SecretSetResponse {
                            success: false,
                            denial: Some(SecretDenialReason::VaultError(format!(
                                "IPC decryption failed: {e}"
                            ))),
                        },
                        ctx.daemon_id,
                    )
                    .await;
                }
            };
            #[cfg(not(feature = "ipc-field-encryption"))]
            let mut store_value = value.as_bytes().to_vec();

            let (success, denial) = match state.vault_for(profile).await {
                Ok(vault) => match vault.store().set(key, &store_value).await {
                    Ok(()) => {
                        vault.flush().await;
                        (true, None)
                    }
                    Err(e) => {
                        tracing::error!(profile = %profile, key, error = %e, "secret set failed");
                        (false, Some(SecretDenialReason::VaultError(e.to_string())))
                    }
                },
                Err(e) => {
                    tracing::error!(profile = %profile, error = %e, "vault access failed");
                    (false, Some(SecretDenialReason::VaultError(e.to_string())))
                }
            };
            // Zeroize the intermediate plaintext copy.
            store_value.zeroize();
            let outcome = if success { "success" } else { "failed" };
            audit_secret_access("set", msg.sender, profile, Some(key), outcome);
            emit_audit_event(
                ctx.client,
                "set",
                profile,
                Some(key),
                msg.sender,
                requester_name,
                outcome,
            )
            .await;
            Some(EventKind::SecretSetResponse { success, denial })
        }

        // -- Secret Delete (profile-scoped) --
        // Check order: lock -> active profile -> identity -> rate limit -> ACL -> vault
        EventKind::SecretDelete { profile, key } => {
            // 1. LOCK CHECK.
            let Some(state) = Some(&mut ctx.vault_state).filter(|s| !s.master_keys.is_empty())
            else {
                audit_secret_access("delete", msg.sender, profile, Some(key), "denied-locked");
                emit_audit_event(
                    ctx.client,
                    "delete",
                    profile,
                    Some(key),
                    msg.sender,
                    msg.verified_sender_name.as_deref(),
                    "denied-locked",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretDeleteResponse {
                        success: false,
                        denial: Some(SecretDenialReason::Locked),
                    },
                    ctx.daemon_id,
                )
                .await;
            };

            // 2. ACTIVE PROFILE CHECK.
            if !state.active_profiles.contains(profile) {
                audit_secret_access(
                    "delete",
                    msg.sender,
                    profile,
                    Some(key),
                    "denied-profile-not-active",
                );
                emit_audit_event(
                    ctx.client,
                    "delete",
                    profile,
                    Some(key),
                    msg.sender,
                    msg.verified_sender_name.as_deref(),
                    "denied-profile-not-active",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretDeleteResponse {
                        success: false,
                        denial: Some(SecretDenialReason::ProfileNotActive),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 3. IDENTITY CHECK.
            let requester_name = msg.verified_sender_name.as_deref();
            check_secret_requester(msg.sender, requester_name);

            // 4. RATE LIMIT CHECK.
            if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
                audit_secret_access("delete", msg.sender, profile, Some(key), "rate-limited");
                emit_audit_event(
                    ctx.client,
                    "delete",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "rate-limited",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretDeleteResponse {
                        success: false,
                        denial: Some(SecretDenialReason::RateLimited),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 5. ACL CHECK.
            if !check_secret_access(ctx.config, profile, requester_name, key) {
                tracing::warn!(
                    audit = "access-denied",
                    requester = %msg.sender,
                    daemon_name = requester_name.unwrap_or("unknown"),
                    profile = %profile,
                    key,
                    "secret access denied by per-profile ACL"
                );
                audit_secret_access("delete", msg.sender, profile, Some(key), "denied-acl");
                emit_audit_event(
                    ctx.client,
                    "delete",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "denied-acl",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretDeleteResponse {
                        success: false,
                        denial: Some(SecretDenialReason::AccessDenied),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 5.5. KEY VALIDATION (defense-in-depth).
            if let Err(e) = validate_secret_key(key) {
                audit_secret_access(
                    "delete",
                    msg.sender,
                    profile,
                    Some(key),
                    "denied-invalid-key",
                );
                emit_audit_event(
                    ctx.client,
                    "delete",
                    profile,
                    Some(key),
                    msg.sender,
                    requester_name,
                    "denied-invalid-key",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretDeleteResponse {
                        success: false,
                        denial: Some(SecretDenialReason::VaultError(e.to_string())),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 6. VAULT ACCESS.
            let (success, denial) = match state.vault_for(profile).await {
                Ok(vault) => match vault.store().delete(key).await {
                    Ok(()) => {
                        vault.flush().await;
                        (true, None)
                    }
                    Err(e) => {
                        tracing::warn!(profile = %profile, key, error = %e, "secret delete failed");
                        (false, Some(SecretDenialReason::VaultError(e.to_string())))
                    }
                },
                Err(e) => {
                    tracing::error!(profile = %profile, error = %e, "vault access failed");
                    (false, Some(SecretDenialReason::VaultError(e.to_string())))
                }
            };
            let outcome = if success { "success" } else { "failed" };
            audit_secret_access("delete", msg.sender, profile, Some(key), outcome);
            emit_audit_event(
                ctx.client,
                "delete",
                profile,
                Some(key),
                msg.sender,
                requester_name,
                outcome,
            )
            .await;
            Some(EventKind::SecretDeleteResponse { success, denial })
        }

        // -- Secret List (profile-scoped) --
        // Check order: lock -> active profile -> identity -> rate limit -> ACL -> vault
        EventKind::SecretList { profile } => {
            // 1. LOCK CHECK.
            let Some(state) = Some(&mut ctx.vault_state).filter(|s| !s.master_keys.is_empty())
            else {
                audit_secret_access("list", msg.sender, profile, None, "denied-locked");
                emit_audit_event(
                    ctx.client,
                    "list",
                    profile,
                    None,
                    msg.sender,
                    msg.verified_sender_name.as_deref(),
                    "denied-locked",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretListResponse {
                        keys: vec![],
                        denial: Some(SecretDenialReason::Locked),
                    },
                    ctx.daemon_id,
                )
                .await;
            };

            // 2. ACTIVE PROFILE CHECK.
            if !state.active_profiles.contains(profile) {
                audit_secret_access(
                    "list",
                    msg.sender,
                    profile,
                    None,
                    "denied-profile-not-active",
                );
                emit_audit_event(
                    ctx.client,
                    "list",
                    profile,
                    None,
                    msg.sender,
                    msg.verified_sender_name.as_deref(),
                    "denied-profile-not-active",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretListResponse {
                        keys: vec![],
                        denial: Some(SecretDenialReason::ProfileNotActive),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 3. IDENTITY CHECK.
            let requester_name = msg.verified_sender_name.as_deref();
            check_secret_requester(msg.sender, requester_name);

            // 4. RATE LIMIT CHECK.
            if !ctx.rate_limiter.check(msg.verified_sender_name.as_deref()) {
                audit_secret_access("list", msg.sender, profile, None, "rate-limited");
                emit_audit_event(
                    ctx.client,
                    "list",
                    profile,
                    None,
                    msg.sender,
                    requester_name,
                    "rate-limited",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretListResponse {
                        keys: vec![],
                        denial: Some(SecretDenialReason::RateLimited),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 5. ACL CHECK (deny list if daemon has explicit empty ACL).
            if !check_secret_list_access(ctx.config, profile, requester_name) {
                tracing::warn!(
                    audit = "access-denied",
                    requester = %msg.sender,
                    daemon_name = requester_name.unwrap_or("unknown"),
                    profile = %profile,
                    "secret list denied by per-profile ACL"
                );
                audit_secret_access("list", msg.sender, profile, None, "denied-acl");
                emit_audit_event(
                    ctx.client,
                    "list",
                    profile,
                    None,
                    msg.sender,
                    requester_name,
                    "denied-acl",
                )
                .await;
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::SecretListResponse {
                        keys: vec![],
                        denial: Some(SecretDenialReason::AccessDenied),
                    },
                    ctx.daemon_id,
                )
                .await;
            }

            // 6. VAULT ACCESS.
            let (keys, denial) = match state.vault_for(profile).await {
                Ok(vault) => (vault.store().list_keys().await.unwrap_or_default(), None),
                Err(e) => {
                    tracing::error!(profile = %profile, error = %e, "vault access failed");
                    (vec![], Some(SecretDenialReason::VaultError(e.to_string())))
                }
            };
            let outcome = if denial.is_some() {
                "failed"
            } else if keys.is_empty() {
                "empty"
            } else {
                "success"
            };
            audit_secret_access("list", msg.sender, profile, None, outcome);
            emit_audit_event(
                ctx.client,
                "list",
                profile,
                None,
                msg.sender,
                requester_name,
                outcome,
            )
            .await;
            Some(EventKind::SecretListResponse { keys, denial })
        }

        // -- Profile Activate (authorize + open vault) --
        // Only process when forwarded by daemon-profile via confirmed_rpc.
        // The CLI broadcasts ProfileActivate to the bus, but daemon-profile is
        // the sole orchestrator — it validates config, unicasts to us, and
        // responds to the CLI. Ignoring broadcast prevents double-processing.
        EventKind::ProfileActivate { profile_name, .. } => {
            if msg.verified_sender_name.as_deref() != Some("daemon-profile") {
                tracing::debug!(sender = ?msg.verified_sender_name, "ignoring profile lifecycle event from non-profile sender");
                return Ok(true);
            }
            // Per-vault check: reject if this specific profile's vault is not unlocked.
            if !ctx.vault_state.master_keys.contains_key(profile_name) {
                tracing::warn!(profile = %profile_name, "profile activate rejected: vault not unlocked");
                return send_response(
                    ctx.client,
                    msg,
                    EventKind::ProfileActivateResponse { success: false },
                    ctx.daemon_id,
                )
                .await;
            }
            let state = &mut ctx.vault_state;
            // Authorize first, then open vault (vault_for gates on active_profiles).
            state.activate_profile(profile_name);
            let success = match state.vault_for(profile_name).await {
                Ok(_) => {
                    tracing::info!(profile = %profile_name, "profile activated");
                    true
                }
                Err(e) => {
                    // Vault open failed — revoke authorization.
                    state.active_profiles.remove(profile_name);
                    tracing::error!(profile = %profile_name, error = %e, "profile activation failed");
                    false
                }
            };
            Some(EventKind::ProfileActivateResponse { success })
        }

        // -- Profile Deactivate (deauthorize, flush JIT, close vault) --
        // Same sender gate as ProfileActivate — only from daemon-profile.
        EventKind::ProfileDeactivate { profile_name, .. } => {
            if msg.verified_sender_name.as_deref() != Some("daemon-profile") {
                tracing::debug!(sender = ?msg.verified_sender_name, "ignoring profile lifecycle event from non-profile sender");
                return Ok(true);
            }
            // Deactivation is idempotent and doesn't require vault to be unlocked.
            ctx.vault_state.deactivate_profile(profile_name).await;
            Some(EventKind::ProfileDeactivateResponse { success: true })
        }

        // -- State reconciliation: daemon-profile queries authoritative state --
        EventKind::SecretsStateRequest => {
            let state = &ctx.vault_state;
            let all_locked = state.master_keys.is_empty();
            let active_profiles = state.active_profiles();
            // Build per-profile lock state from config profile names.
            let lock_state: std::collections::BTreeMap<TrustProfileName, bool> = ctx
                .config
                .profiles
                .keys()
                .filter_map(|name| TrustProfileName::try_from(name.as_str()).ok())
                .map(|name| {
                    let is_locked = !state.master_keys.contains_key(&name);
                    (name, is_locked)
                })
                .collect();
            Some(EventKind::SecretsStateResponse {
                locked: all_locked,
                active_profiles,
                lock_state,
            })
        }

        // -- Ignore other events --
        _ => None,
    };

    if let Some(event) = response_event {
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
    }

    Ok(true)
}

/// Send a correlated response to an inbound request.
async fn send_response(
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

/// Result of a successful profile unlock.
struct UnlockResult {
    /// Per-profile master key (mlock'd, zeroize-on-drop).
    master_key: SecureBytes,
    /// Pre-verified vault store, if a vault DB existed at unlock time.
    /// Cached to avoid redundant SQLCipher open on first ProfileActivate.
    verified_store: Option<SqlCipherStore>,
}

/// Unlock a specific profile's vault by deriving its master key from a
/// per-profile salt via Argon2id. Fast path uses platform keyring.
///
/// Each profile has its own salt at `{config_dir}/vaults/{profile}.salt`.
/// First unlock generates the salt. Subsequent unlocks read existing salt.
/// If a vault DB exists, the derived key is verified against it and the
/// opened store is returned for caching.
async fn unlock_profile(
    password: &[u8],
    profile: &TrustProfileName,
    config_dir: &Path,
) -> core_types::Result<UnlockResult> {
    let salt_file = profile_salt_path(config_dir, profile);

    // Fast path: try per-profile keyring retrieval (avoids Argon2id).
    #[cfg(target_os = "linux")]
    if salt_file.exists() {
        let salt_bytes = std::fs::read(&salt_file)
            .map_err(|e| core_types::Error::Config(format!("failed to read profile salt: {e}")))?;
        if let Some(master_key) = keyring_retrieve_profile(password, &salt_bytes, profile).await {
            return Ok(UnlockResult {
                master_key,
                verified_store: None,
            });
        }
    }

    // Derive master key: load existing salt or generate new one.
    let master_key = if salt_file.exists() {
        let salt = load_salt(&salt_file)?;
        derive_master_key(password, &salt)?
    } else {
        let new_salt = generate_profile_salt(&salt_file)?;
        tracing::info!(profile = %profile, path = %salt_file.display(), "per-profile salt generated");
        derive_master_key(password, &new_salt)?
    };

    // Verify against existing vault DB if it exists.
    let vault_path = config_dir.join("vaults").join(format!("{profile}.db"));
    let verified_store = if vault_path.exists() {
        let vault_key = core_crypto::derive_vault_key(master_key.as_bytes(), profile);
        let vp = vault_path;
        let result = tokio::task::spawn_blocking(move || SqlCipherStore::open(&vp, &vault_key))
            .await
            .map_err(|e| core_types::Error::Secrets(format!("spawn_blocking: {e}")))?;

        match result {
            Ok(store) => {
                tracing::info!(profile = %profile, "vault key verified");
                Some(store)
            }
            Err(e) => {
                tracing::warn!(error = %e, profile = %profile, "vault key verification failed — wrong password");
                return Err(core_types::Error::Secrets(
                    "wrong password: vault key verification failed".into(),
                ));
            }
        }
    } else {
        None
    };

    Ok(UnlockResult {
        master_key,
        verified_store,
    })
}

/// Wait for SIGTERM (Unix) or simulate on non-Unix.
async fn sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sig = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
        sig.recv().await;
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}

/// Apply Landlock + seccomp sandbox (Linux only).
#[cfg(target_os = "linux")]
fn apply_sandbox() {
    use platform_linux::sandbox::{FsAccess, LandlockRule, SeccompProfile, apply_sandbox};

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/run/user/1000".into());

    let config_dir = core_config::config_dir();

    let pds_dir = PathBuf::from(&runtime_dir).join("pds");
    let keys_dir = pds_dir.join("keys");

    // Resolve config symlink targets (e.g. /nix/store) before Landlock.
    // On NixOS, config.toml is a symlink into /nix/store — without this,
    // config hot-reload fails because Landlock blocks reading the target.
    let config_real_dirs = core_config::resolve_config_real_dirs(None);

    let mut rules = vec![
        // Config dir: vault DBs + salt stored here.
        LandlockRule {
            path: config_dir,
            access: FsAccess::ReadWrite,
        },
        LandlockRule {
            path: keys_dir.clone(),
            access: FsAccess::ReadOnly,
        },
        // Bus public key: needed if reconnect ever happens.
        LandlockRule {
            path: pds_dir.join("bus.pub"),
            access: FsAccess::ReadOnly,
        },
        // Bus socket: connect + read/write IPC traffic.
        LandlockRule {
            path: pds_dir.join("bus.sock"),
            access: FsAccess::ReadWriteFile,
        },
        // D-Bus socket — non-directory fd, use ReadWriteFile to avoid
        // PartiallyEnforced from directory-only landlock flags.
        LandlockRule {
            path: PathBuf::from(&runtime_dir).join("bus"),
            access: FsAccess::ReadWriteFile,
        },
    ];

    // systemd notify socket: sd_notify(READY=1) and watchdog keepalives
    // need connect+sendto access to $NOTIFY_SOCKET after Landlock is applied.
    // Abstract sockets (prefixed '@') bypass Landlock AccessFs rules.
    if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET")
        && !notify_socket.starts_with('@')
    {
        let path = PathBuf::from(&notify_socket);
        if path.exists() {
            rules.push(LandlockRule {
                path,
                access: FsAccess::ReadWriteFile,
            });
        }
    }

    // Config symlink targets (e.g. /nix/store paths) need read access
    // for config hot-reload to follow symlinks after Landlock is applied.
    for dir in &config_real_dirs {
        rules.push(LandlockRule {
            path: dir.clone(),
            access: FsAccess::ReadOnly,
        });
    }

    let seccomp = SeccompProfile {
        daemon_name: "daemon-secrets".into(),
        allowed_syscalls: vec![
            // I/O basics
            "read".into(),
            "write".into(),
            "close".into(),
            "openat".into(),
            "lseek".into(),
            "pread64".into(),
            "fstat".into(),
            "stat".into(),
            "newfstatat".into(),
            "statx".into(),
            "access".into(),
            "unlink".into(),
            "fcntl".into(),
            "flock".into(),
            "fdatasync".into(),
            "mkdir".into(),
            "getdents64".into(),
            // Memory (secrets needs mlock/munlock/madvise for zeroization)
            "mmap".into(),
            "mprotect".into(),
            "munmap".into(),
            "mlock".into(),
            "munlock".into(),
            "madvise".into(),
            "brk".into(),
            // Process / threading
            "futex".into(),
            "clone3".into(),
            "clone".into(),
            "set_robust_list".into(),
            "set_tid_address".into(),
            "rseq".into(),
            "sched_getaffinity".into(),
            "prlimit64".into(),
            "prctl".into(),
            "getpid".into(),
            "gettid".into(),
            "getuid".into(),
            "geteuid".into(),
            "kill".into(),
            // Epoll / event loop (tokio)
            "epoll_wait".into(),
            "epoll_ctl".into(),
            "epoll_create1".into(),
            "eventfd2".into(),
            "poll".into(),
            "ppoll".into(),
            // Timers (tokio runtime)
            "clock_gettime".into(),
            "timer_create".into(),
            "timer_settime".into(),
            "timer_delete".into(),
            // Networking / IPC
            "socket".into(),
            "connect".into(),
            "sendto".into(),
            "recvfrom".into(),
            "socketpair".into(),
            "sendmsg".into(),
            "recvmsg".into(),
            "shutdown".into(),
            "getsockopt".into(),
            "getsockname".into(),
            "getpeername".into(),
            "setsockopt".into(),
            // D-Bus credential passing (KeyLocker / SecretService)
            "getresuid".into(),
            "getresgid".into(),
            "getgid".into(),
            "getegid".into(),
            // D-Bus / SSH agent I/O
            "writev".into(),
            "readv".into(),
            "readlink".into(),
            "readlinkat".into(),
            "uname".into(),
            "getcwd".into(),
            // Timing
            "nanosleep".into(),
            "clock_nanosleep".into(),
            // Signals
            "sigaltstack".into(),
            "rt_sigaction".into(),
            "rt_sigprocmask".into(),
            "rt_sigreturn".into(),
            "tgkill".into(),
            // Config hot-reload (notify crate uses inotify)
            "inotify_init1".into(),
            "inotify_add_watch".into(),
            "inotify_rm_watch".into(),
            // Misc
            "exit_group".into(),
            "exit".into(),
            "getrandom".into(),
            "restart_syscall".into(),
            "pipe2".into(),
            "dup".into(),
            "ioctl".into(),
        ],
    };

    match apply_sandbox(&rules, &seccomp) {
        Ok(status) => {
            tracing::info!(?status, "sandbox applied");
        }
        Err(e) => {
            panic!("sandbox application failed: {e} — refusing to run unsandboxed");
        }
    }
}

// ============================================================================
// Platform keyring integration (ADR-SEC-001)
//
// The raw master key NEVER touches the platform keyring. Instead:
// 1. A KEK (key-encrypting-key) is derived from password+salt via BLAKE3
//    with a dedicated context string independent from Argon2id derivation.
// 2. The master key is AES-256-GCM encrypted under the KEK with a random nonce.
// 3. The wrapped blob [12-byte nonce || ciphertext || 16-byte tag] is stored.
// 4. On retrieval, the KEK is re-derived from password+salt, and the blob
//    is decrypted. GCM tag verification rejects wrong passwords.
// ============================================================================

/// KeyLocker service constant for platform keyring.
const KEYLOCKER_SERVICE: &str = "pds";

/// Per-profile keyring account name.
fn keylocker_account(profile: &TrustProfileName) -> String {
    format!("vault-key-{profile}")
}

/// Wrap a profile's master key with a KEK and store in the platform keyring.
///
/// Wire format: `[12-byte random nonce][ciphertext + 16-byte GCM tag]`
#[cfg(target_os = "linux")]
async fn keyring_store_profile(
    master_key: &SecureBytes,
    password: &[u8],
    salt: &[u8],
    profile: &TrustProfileName,
) {
    use core_secrets::KeyLocker;

    let kek = core_crypto::derive_kek(password, salt);
    let enc_key = match core_crypto::EncryptionKey::from_bytes(
        kek.as_bytes().try_into().unwrap_or(&[0u8; 32]),
    ) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, profile = %profile, "keyring: KEK construction failed");
            return;
        }
    };

    let mut nonce = [0u8; 12];
    if let Err(e) = getrandom::getrandom(&mut nonce) {
        tracing::warn!(error = %e, "keyring: nonce generation failed");
        return;
    }

    let ciphertext = match enc_key.encrypt(&nonce, master_key.as_bytes()) {
        Ok(ct) => ct,
        Err(e) => {
            tracing::warn!(error = %e, "keyring: master key wrapping failed");
            return;
        }
    };

    let mut wrapped = Vec::with_capacity(12 + ciphertext.len());
    wrapped.extend_from_slice(&nonce);
    wrapped.extend(ciphertext);

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::warn!(error = %e, "keyring: failed to connect to session bus");
            return;
        }
    };
    let account = keylocker_account(profile);
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);
    match locker
        .store_wrapped_key(KEYLOCKER_SERVICE, &account, &wrapped)
        .await
    {
        Ok(()) => tracing::info!(profile = %profile, "KEK-wrapped vault key stored in keyring"),
        Err(e) => tracing::warn!(error = %e, profile = %profile, "keyring: store failed"),
    }
}

/// Retrieve and unwrap a profile's master key from the platform keyring.
#[cfg(target_os = "linux")]
async fn keyring_retrieve_profile(
    password: &[u8],
    salt: &[u8],
    profile: &TrustProfileName,
) -> Option<SecureBytes> {
    use core_secrets::KeyLocker;

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::debug!(error = %e, "keyring: failed to connect to session bus");
            return None;
        }
    };
    let account = keylocker_account(profile);
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);

    match locker.has_wrapped_key(KEYLOCKER_SERVICE, &account).await {
        Ok(true) => {}
        Ok(false) => return None,
        Err(e) => {
            tracing::debug!(error = %e, "keyring: has_wrapped_key check failed");
            return None;
        }
    }

    let wrapped = match locker
        .retrieve_wrapped_key(KEYLOCKER_SERVICE, &account)
        .await
    {
        Ok(w) => w,
        Err(e) => {
            tracing::debug!(error = %e, "keyring: retrieve failed");
            return None;
        }
    };

    if wrapped.len() < 60 {
        tracing::warn!(len = wrapped.len(), "keyring: wrapped blob too short");
        return None;
    }

    let kek = core_crypto::derive_kek(password, salt);
    let enc_key = match core_crypto::EncryptionKey::from_bytes(
        kek.as_bytes().try_into().unwrap_or(&[0u8; 32]),
    ) {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!(error = %e, "keyring: KEK construction failed");
            return None;
        }
    };

    let nonce: [u8; 12] = wrapped.as_bytes()[..12].try_into().ok()?;
    let ciphertext = &wrapped.as_bytes()[12..];

    match enc_key.decrypt(&nonce, ciphertext) {
        Ok(master_key) => {
            tracing::info!(profile = %profile, "vault key unwrapped from keyring (fast path)");
            Some(master_key)
        }
        Err(_) => {
            tracing::debug!(profile = %profile, "keyring: GCM tag failed (wrong password or corrupted)");
            None
        }
    }
}

/// Delete a specific profile's wrapped key from the platform keyring.
#[cfg(target_os = "linux")]
async fn keyring_delete_profile(profile: &TrustProfileName) {
    use core_secrets::KeyLocker;

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::warn!(error = %e, "keyring: failed to connect to session bus");
            return;
        }
    };
    let account = keylocker_account(profile);
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);
    match locker.delete_wrapped_key(KEYLOCKER_SERVICE, &account).await {
        Ok(()) => tracing::info!(profile = %profile, "wrapped vault key deleted from keyring"),
        Err(e) => tracing::debug!(error = %e, profile = %profile, "keyring: delete failed"),
    }
}

/// Delete wrapped keys for all given profiles from the platform keyring (best-effort).
#[cfg(target_os = "linux")]
async fn keyring_delete_all(profiles: &[TrustProfileName]) {
    use core_secrets::KeyLocker;

    let bus = match platform_linux::dbus::SessionBus::connect().await {
        Ok(b) => Arc::new(b),
        Err(e) => {
            tracing::warn!(error = %e, "keyring: failed to connect to session bus");
            return;
        }
    };
    let locker = key_locker_linux::SecretServiceKeyLocker::new(bus);
    for profile in profiles {
        let account = keylocker_account(profile);
        if let Err(e) = locker.delete_wrapped_key(KEYLOCKER_SERVICE, &account).await {
            tracing::debug!(error = %e, profile = %profile, "keyring: delete failed (may not exist)");
        }
    }
    tracing::info!(
        count = profiles.len(),
        "per-profile keyring entries deleted"
    );
}

fn init_logging(format: &str) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .init();
        }
        _ => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_crypto::SecureBytes;
    use std::collections::{HashMap, HashSet};
    use std::time::Duration;

    /// Create a test master key (deterministic, not for production use).
    fn test_master_key() -> SecureBytes {
        let mut key = vec![0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(7);
        }
        SecureBytes::new(key)
    }

    /// Create a VaultState with a test master key for "work" profile.
    fn make_vault_state(config_dir: &std::path::Path) -> VaultState {
        let mut master_keys = HashMap::new();
        // Pre-unlock "work" and "alpha" and "beta" profiles for tests.
        for name in &["work", "alpha", "beta", "never-activated"] {
            let p = profile(name);
            master_keys.insert(p, test_master_key());
        }
        VaultState {
            master_keys,
            vaults: HashMap::new(),
            active_profiles: HashSet::new(),
            ttl: Duration::from_secs(60),
            config_dir: config_dir.to_path_buf(),
        }
    }

    fn profile(name: &str) -> TrustProfileName {
        TrustProfileName::try_from(name).expect("valid profile name")
    }

    // vault_for() returns error if profile not in active_profiles
    #[tokio::test]
    async fn test_vault_for_rejects_inactive_profile() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let p = profile("work");
        let result = state.vault_for(&p).await;
        assert!(result.is_err(), "vault_for must reject inactive profile");
        let err = result.err().expect("expected error").to_string();
        assert!(
            err.contains("not active"),
            "error must mention 'not active', got: {err}"
        );
    }

    // vault_for() returns error if profile is active but not unlocked
    #[tokio::test]
    async fn test_vault_for_rejects_active_but_not_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let p = profile("not-in-master-keys");
        state.active_profiles.insert(p.clone());
        let result = state.vault_for(&p).await;
        assert!(
            result.is_err(),
            "vault_for must reject profile without master key"
        );
        let err = result.err().expect("expected error").to_string();
        assert!(
            err.contains("not unlocked"),
            "error must mention 'not unlocked', got: {err}"
        );
    }

    // activate then vault_for succeeds (lazy open)
    #[tokio::test]
    async fn test_activate_then_vault_for_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let p = profile("work");
        state.activate_profile(&p);
        let result = state.vault_for(&p).await;
        assert!(
            result.is_ok(),
            "vault_for must succeed after activation: {:?}",
            result.err()
        );
    }

    // Deactivate then vault_for rejects
    #[tokio::test]
    async fn test_deactivate_then_vault_for_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let p = profile("work");
        state.activate_profile(&p);
        let _ = state.vault_for(&p).await; // open vault
        state.deactivate_profile(&p).await;
        let result = state.vault_for(&p).await;
        assert!(result.is_err(), "vault_for must reject after deactivation");
    }

    // deactivate on already-inactive profile is idempotent
    #[tokio::test]
    async fn test_deactivate_inactive_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let p = profile("never-activated");
        // Must not panic or error
        state.deactivate_profile(&p).await;
    }

    // Full round-trip: activate -> deactivate -> activate -> vault_for succeeds
    #[tokio::test]
    async fn test_activate_deactivate_reactivate_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let p = profile("work");

        state.activate_profile(&p);
        assert!(state.vault_for(&p).await.is_ok());

        state.deactivate_profile(&p).await;
        assert!(state.vault_for(&p).await.is_err());

        state.activate_profile(&p);
        assert!(
            state.vault_for(&p).await.is_ok(),
            "vault_for must succeed after reactivation"
        );
    }

    // active_profiles() returns the authorization set, not vault keys
    #[tokio::test]
    async fn test_active_profiles_returns_authorization_set() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let p1 = profile("alpha");
        let p2 = profile("beta");

        state.activate_profile(&p1);
        state.activate_profile(&p2);

        let active: HashSet<TrustProfileName> = state.active_profiles().into_iter().collect();
        assert!(active.contains(&p1));
        assert!(active.contains(&p2));
        assert_eq!(active.len(), 2);

        // Deactivate one — only one remains
        state.deactivate_profile(&p1).await;
        let active: HashSet<TrustProfileName> = state.active_profiles().into_iter().collect();
        assert!(!active.contains(&p1));
        assert!(active.contains(&p2));
        assert_eq!(active.len(), 1);

        // Verify it returns authorization set not vault keys:
        // Activate p1 again but do NOT call vault_for (no vault opened).
        // active_profiles must still include p1 even though no vault is open.
        state.activate_profile(&p1);
        let active: HashSet<TrustProfileName> = state.active_profiles().into_iter().collect();
        assert!(
            active.contains(&p1),
            "active_profiles must include authorized profile even without open vault"
        );
        // But vaults map should NOT contain p1 (we didn't call vault_for)
        assert!(
            !state.vaults.contains_key(&p1),
            "vaults map must not contain profile that was only authorized, not opened"
        );
    }

    // lock clears active_profiles
    #[tokio::test]
    async fn test_lock_clears_active_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let p1 = profile("alpha");
        let p2 = profile("beta");

        state.activate_profile(&p1);
        state.activate_profile(&p2);
        assert_eq!(state.active_profiles().len(), 2);

        // Simulate lock: clear active profiles and master keys (as the lock handler does)
        state.active_profiles.clear();
        state.master_keys.clear();
        assert!(
            state.active_profiles().is_empty(),
            "active_profiles must be empty after lock"
        );
        assert!(
            state.master_keys.is_empty(),
            "master_keys must be empty after lock"
        );
    }

    // Unlock initializes empty active_profiles
    #[test]
    fn test_unlock_initializes_empty_active_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_vault_state(dir.path());
        assert!(
            state.active_profiles().is_empty(),
            "fresh VaultState must have empty active_profiles"
        );
    }

    // -- A. Independent master keys --

    #[tokio::test]
    async fn test_independent_master_keys_per_profile() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = VaultState {
            master_keys: HashMap::new(),
            vaults: HashMap::new(),
            active_profiles: HashSet::new(),
            ttl: Duration::from_secs(60),
            config_dir: dir.path().to_path_buf(),
        };
        let a = profile("alpha");
        let b = profile("beta");
        state.master_keys.insert(a.clone(), test_master_key());
        state.activate_profile(&a);
        state.activate_profile(&b);

        assert!(
            state.vault_for(&a).await.is_ok(),
            "profile with master key should succeed"
        );
        let result_b = state.vault_for(&b).await;
        assert!(result_b.is_err(), "profile without master key should fail");
        let err = result_b.err().unwrap().to_string();
        assert!(
            err.contains("not unlocked"),
            "profile without master key should fail: {err}"
        );
    }

    #[tokio::test]
    async fn test_per_profile_lock_isolates_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let a = profile("alpha");
        let b = profile("beta");
        state.activate_profile(&a);
        state.activate_profile(&b);
        assert!(state.vault_for(&a).await.is_ok());
        assert!(state.vault_for(&b).await.is_ok());

        state.master_keys.remove(&a);
        let result_a = state.vault_for(&a).await;
        assert!(result_a.is_err(), "locked profile should fail");
        let err = result_a.err().unwrap().to_string();
        assert!(
            err.contains("not unlocked"),
            "locked profile should fail: {err}"
        );
        assert!(
            state.vault_for(&b).await.is_ok(),
            "other profile should still work"
        );
    }

    #[tokio::test]
    async fn test_lock_all_clears_all_master_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let profiles: Vec<_> = ["alpha", "beta", "work"]
            .iter()
            .map(|n| profile(n))
            .collect();
        for p in &profiles {
            state.activate_profile(p);
            let _ = state.vault_for(p).await;
        }
        state.master_keys.clear();
        for p in &profiles {
            assert!(
                state.vault_for(p).await.is_err(),
                "vault_for should fail after clearing all keys"
            );
        }
    }

    #[tokio::test]
    async fn test_vault_caching_survives_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        let p = profile("work");
        state.activate_profile(&p);
        assert!(state.vault_for(&p).await.is_ok());
        assert!(
            state.vaults.contains_key(&p),
            "vault should be cached after first access"
        );
        assert!(
            state.vault_for(&p).await.is_ok(),
            "second vault_for should succeed from cache"
        );
    }

    #[tokio::test]
    async fn test_different_master_keys_produce_independent_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let mut key_a = vec![0u8; 32];
        key_a[0] = 0xAA;
        let mut key_b = vec![0u8; 32];
        key_b[0] = 0xBB;

        let mut state = VaultState {
            master_keys: HashMap::new(),
            vaults: HashMap::new(),
            active_profiles: HashSet::new(),
            ttl: Duration::from_secs(60),
            config_dir: dir.path().to_path_buf(),
        };
        let pa = profile("alpha");
        let pb = profile("beta");
        state
            .master_keys
            .insert(pa.clone(), SecureBytes::new(key_a));
        state
            .master_keys
            .insert(pb.clone(), SecureBytes::new(key_b));
        state.activate_profile(&pa);
        state.activate_profile(&pb);

        let vault_a = state.vault_for(&pa).await.unwrap();
        vault_a.store().set("key1", b"value-a").await.unwrap();

        let vault_b = state.vault_for(&pb).await.unwrap();
        vault_b.store().set("key1", b"value-b").await.unwrap();

        let val_a = state
            .vault_for(&pa)
            .await
            .unwrap()
            .store()
            .get("key1")
            .await
            .unwrap();
        let val_b = state
            .vault_for(&pb)
            .await
            .unwrap()
            .store()
            .get("key1")
            .await
            .unwrap();
        assert_eq!(
            val_a.as_bytes(),
            b"value-a",
            "vault A should have its own data"
        );
        assert_eq!(
            val_b.as_bytes(),
            b"value-b",
            "vault B should have its own data"
        );
    }

    // -- B. Salt and Key Derivation --

    #[test]
    fn test_profile_salt_path_format() {
        let p = profile("work");
        let path = profile_salt_path(Path::new("/tmp/config"), &p);
        assert_eq!(path, PathBuf::from("/tmp/config/vaults/work.salt"));
    }

    #[test]
    fn test_generate_profile_salt_creates_16_byte_file() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("vaults").join("test.salt");
        let salt = generate_profile_salt(&sp).unwrap();
        assert_eq!(salt.len(), 16);
        let on_disk = std::fs::read(&sp).unwrap();
        assert_eq!(on_disk.len(), 16);
    }

    #[test]
    fn test_generate_profile_salt_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("deeply").join("nested").join("test.salt");
        assert!(!sp.parent().unwrap().exists());
        let result = generate_profile_salt(&sp);
        assert!(result.is_ok(), "should create parent directories");
        assert!(sp.exists());
    }

    #[test]
    fn test_load_salt_reads_back_generated() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("vaults").join("test.salt");
        let generated = generate_profile_salt(&sp).unwrap();
        let loaded = load_salt(&sp).unwrap();
        assert_eq!(generated, loaded, "loaded salt must match generated salt");
    }

    #[test]
    fn test_load_salt_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().join("bad.salt");
        std::fs::write(&sp, [0u8; 15]).unwrap();
        let err = load_salt(&sp).unwrap_err().to_string();
        assert!(
            err.contains("not 16 bytes"),
            "should reject wrong length: {err}"
        );
    }

    #[test]
    fn test_derive_master_key_deterministic() {
        let salt = [42u8; 16];
        let k1 = derive_master_key(b"password", &salt).unwrap();
        let k2 = derive_master_key(b"password", &salt).unwrap();
        assert_eq!(
            k1.as_bytes(),
            k2.as_bytes(),
            "same inputs must produce same key"
        );

        let k3 = derive_master_key(b"different", &salt).unwrap();
        assert_ne!(
            k1.as_bytes(),
            k3.as_bytes(),
            "different password must produce different key"
        );

        let other_salt = [99u8; 16];
        let k4 = derive_master_key(b"password", &other_salt).unwrap();
        assert_ne!(
            k1.as_bytes(),
            k4.as_bytes(),
            "different salt must produce different key"
        );
    }

    // -- C. unlock_profile --

    #[tokio::test]
    async fn test_unlock_profile_generates_salt_and_returns_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile("fresh");
        let salt_file = profile_salt_path(dir.path(), &p);
        assert!(!salt_file.exists());

        let result = unlock_profile(b"my-password", &p, dir.path()).await;
        assert!(
            result.is_ok(),
            "first unlock should succeed: {:?}",
            result.err()
        );
        assert!(salt_file.exists(), "salt file should be created");
    }

    #[tokio::test]
    async fn test_unlock_profile_same_password_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile("deterministic");

        let r1 = unlock_profile(b"same-pass", &p, dir.path()).await.unwrap();
        let r2 = unlock_profile(b"same-pass", &p, dir.path()).await.unwrap();
        assert_eq!(
            r1.master_key.as_bytes(),
            r2.master_key.as_bytes(),
            "same password should derive same key"
        );
    }

    #[tokio::test]
    async fn test_unlock_profile_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile("wrongpass");

        let r1 = unlock_profile(b"correct-pass", &p, dir.path())
            .await
            .unwrap();
        // Open a vault with the correct key to create the DB file.
        let vault_key = core_crypto::derive_vault_key(r1.master_key.as_bytes(), &p);
        let db_path = dir.path().join("vaults").join(format!("{p}.db"));
        std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let _store = SqlCipherStore::open(&db_path, &vault_key).unwrap();
        drop(_store);

        let r2 = unlock_profile(b"wrong-pass", &p, dir.path()).await;
        assert!(r2.is_err(), "wrong password should fail");
        let err = r2.err().unwrap().to_string();
        assert!(
            err.contains("wrong password"),
            "error should mention wrong password: {err}"
        );
    }

    #[tokio::test]
    async fn test_unlock_profile_returns_verified_store_when_vault_exists() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile("withvault");

        let r1 = unlock_profile(b"pass123", &p, dir.path()).await.unwrap();
        // Create the vault DB.
        let vault_key = core_crypto::derive_vault_key(r1.master_key.as_bytes(), &p);
        let db_path = dir.path().join("vaults").join(format!("{p}.db"));
        std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let _store = SqlCipherStore::open(&db_path, &vault_key).unwrap();
        drop(_store);

        let r2 = unlock_profile(b"pass123", &p, dir.path()).await.unwrap();
        assert!(
            r2.verified_store.is_some(),
            "should return verified store when vault DB exists"
        );
    }

    #[tokio::test]
    async fn test_unlock_profile_returns_none_store_when_no_vault_db() {
        let dir = tempfile::tempdir().unwrap();
        let p = profile("novault");

        let result = unlock_profile(b"pass123", &p, dir.path()).await.unwrap();
        assert!(
            result.verified_store.is_none(),
            "should return None when no vault DB exists"
        );
    }

    // -- F. Keyring account naming --

    #[test]
    fn test_keylocker_account_format() {
        let p = profile("work");
        assert_eq!(keylocker_account(&p), "vault-key-work");
    }
}
