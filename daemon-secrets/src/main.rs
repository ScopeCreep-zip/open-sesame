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
mod crud;
mod dispatch;
mod keyring;
mod rate_limit;
mod sandbox;
mod unlock;
mod vault;

use dispatch::MessageContext;
use rate_limit::SecretRateLimiter;
use vault::{PARTIAL_UNLOCK_SWEEP_INTERVAL_SECS, VaultState};

use anyhow::Context;
use clap::Parser;
use core_ipc::BusClient;
use core_types::{DaemonId, EventKind, SecurityLevel, TrustProfileName};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // -- Logging --
    init_logging(&cli.log_format)?;

    tracing::info!("daemon-secrets starting");

    // -- Process hardening --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    #[cfg(target_os = "linux")]
    platform_linux::security::apply_resource_limits(&platform_linux::security::ResourceLimits {
        nofile: 1024,
        memlock_bytes: 64 * 1024 * 1024, // 64M
    });

    // -- Directory bootstrap --
    core_config::bootstrap_dirs();

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
    sandbox::apply_sandbox();

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
        partial_unlocks: HashMap::new(),
        ttl: Duration::from_secs(cli.ttl),
        config_dir: config_dir.clone(),
    };
    let mut rate_limiter = SecretRateLimiter::new();

    let mut watchdog_count: u64 = 0;
    let mut partial_sweep =
        tokio::time::interval(Duration::from_secs(PARTIAL_UNLOCK_SWEEP_INTERVAL_SECS));
    partial_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = partial_sweep.tick() => {
                let now = tokio::time::Instant::now();
                let expired: Vec<TrustProfileName> = vault_state
                    .partial_unlocks
                    .iter()
                    .filter(|(_, p)| now >= p.deadline)
                    .map(|(name, _)| name.clone())
                    .collect();
                for name in &expired {
                    vault_state.partial_unlocks.remove(name);
                    tracing::info!(profile = %name, "expired partial unlock state removed");
                }
            }
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
                match dispatch::handle_message(&msg, &mut ctx).await {
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
        keyring::keyring_delete_all(&profile_names).await;
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
    use crate::keyring::keylocker_account;
    use crate::unlock::{
        derive_master_key, generate_profile_salt, load_salt, profile_salt_path, unlock_profile,
    };
    use crate::vault::{PartialUnlock, VaultState};

    use core_crypto::SecureBytes;
    use core_secrets::{SecretsStore, SqlCipherStore};
    use core_types::{AuthFactorId, TrustProfileName};
    use std::collections::{HashMap, HashSet};
    use std::path::{Path, PathBuf};
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
            partial_unlocks: HashMap::new(),
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
            partial_unlocks: HashMap::new(),
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
            partial_unlocks: HashMap::new(),
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

    // -- G. PartialUnlock state machine --

    #[tokio::test]
    async fn test_partial_unlock_is_complete_when_no_remaining() {
        let partial = PartialUnlock {
            received_factors: HashMap::new(),
            remaining_required: HashSet::new(),
            remaining_additional: 0,
            deadline: tokio::time::Instant::now() + Duration::from_secs(120),
        };
        assert!(partial.is_complete());
        assert!(!partial.is_expired());
    }

    #[tokio::test]
    async fn test_partial_unlock_not_complete_with_required() {
        let mut remaining = HashSet::new();
        remaining.insert(AuthFactorId::Password);
        let partial = PartialUnlock {
            received_factors: HashMap::new(),
            remaining_required: remaining,
            remaining_additional: 0,
            deadline: tokio::time::Instant::now() + Duration::from_secs(120),
        };
        assert!(!partial.is_complete());
    }

    #[tokio::test]
    async fn test_partial_unlock_not_complete_with_additional() {
        let partial = PartialUnlock {
            received_factors: HashMap::new(),
            remaining_required: HashSet::new(),
            remaining_additional: 1,
            deadline: tokio::time::Instant::now() + Duration::from_secs(120),
        };
        assert!(!partial.is_complete());
    }

    #[tokio::test]
    async fn test_partial_unlock_expired() {
        let partial = PartialUnlock {
            received_factors: HashMap::new(),
            remaining_required: HashSet::new(),
            remaining_additional: 0,
            deadline: tokio::time::Instant::now() - Duration::from_secs(1),
        };
        assert!(partial.is_expired());
    }

    #[tokio::test]
    async fn test_partial_unlock_factor_tracking() {
        let mut remaining = HashSet::new();
        remaining.insert(AuthFactorId::Password);
        remaining.insert(AuthFactorId::SshAgent);

        let mut partial = PartialUnlock {
            received_factors: HashMap::new(),
            remaining_required: remaining,
            remaining_additional: 0,
            deadline: tokio::time::Instant::now() + Duration::from_secs(120),
        };

        assert!(!partial.is_complete());

        // Submit password factor.
        let key = SecureBytes::new(vec![1u8; 32]);
        partial.received_factors.insert(AuthFactorId::Password, key);
        partial.remaining_required.remove(&AuthFactorId::Password);
        assert!(!partial.is_complete());

        // Submit SSH factor.
        let key2 = SecureBytes::new(vec![2u8; 32]);
        partial
            .received_factors
            .insert(AuthFactorId::SshAgent, key2);
        partial.remaining_required.remove(&AuthFactorId::SshAgent);
        assert!(partial.is_complete());
        assert_eq!(partial.received_factors.len(), 2);
    }
}
