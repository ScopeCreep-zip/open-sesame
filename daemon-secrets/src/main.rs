//! daemon-secrets: Secrets broker daemon.
//!
//! Manages encrypted per-profile secret vaults with JIT caching and IPC-based
//! request handling. Connects to the IPC bus as a client, accepts
//! `FactorSubmit` messages that unlock vaults under each vault's auth
//! policy, then serves SecretGet/Set/Delete/List requests against
//! SQLCipher-backed stores keyed with per-profile vault keys, derived under
//! each vault's metadata `hkdf`.
//!
//! # Startup sequence
//!
//! 1. Parse CLI, init logging, load config
//! 2. Apply Landlock + seccomp sandbox, while the process has one thread
//! 3. Start the async runtime; connect to the IPC bus as client
//! 4. Enter IPC event loop — vaults unlocked independently per profile
//! 5. Each vault unlocks when its submitted factors satisfy its auth policy
//! 6. Vaults opened lazily on first access after unlock + profile activation
//!
//! Multiple profiles may have open vaults concurrently. Each profile has its
//! own factors, salt, and master key. Every secret RPC carries a `profile`
//! field identifying which vault to query.
//!
//! # Security constraints
//!
//! - Landlock: bus client files, config dir (read/write: vaults live under
//!   it), systemd notification socket
//! - seccomp: restricted syscall set (no network, no ptrace)
//! - systemd: `PrivateNetwork=yes` (no network access)
//!
//! # Key hierarchy (ADR-SEC-002)
//!
//! ```text
//! random master key, wrapped per factor (password: KEK under the vault's kdf;
//!   SSH agent: KEK from the challenge signature)
//!   → client unwraps → FactorSubmit → policy satisfied → derive_key(vault hkdf) → vault key
//! ```

mod acl;
mod crud;
mod dispatch;
mod rate_limit;
mod sandbox;
mod unlock;
mod vault;

use dispatch::MessageContext;
use rate_limit::SecretRateLimiter;
use vault::{PARTIAL_UNLOCK_SWEEP_INTERVAL, VaultState};

use anyhow::Context;
use clap::Parser;
use core_daemon::{DaemonIdentity, EventLoop, LogFormat, Shutdown, Wake};
use std::time::Duration;

const IDENTITY: DaemonIdentity = DaemonIdentity {
    daemon: core_types::Daemon::Secrets,
    version: env!("CARGO_PKG_VERSION"),
    capabilities: &["secrets"],
};

/// PDS secrets broker daemon.
#[derive(Parser, Debug)]
#[command(name = IDENTITY.daemon.name(), about = "PDS secrets broker")]
struct Cli {
    /// JIT cache TTL in seconds.
    #[arg(long, default_value = "300", env = "PDS_SECRET_TTL")]
    ttl: u64,

    #[arg(long, value_enum, default_value = "json", env = "PDS_LOG_FORMAT")]
    log_format: LogFormat,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    core_daemon::init_logging(cli.log_format)?;

    tracing::info!("daemon-secrets starting");

    // -- Process hardening --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    #[cfg(target_os = "linux")]
    platform_linux::security::apply_resource_limits(&platform_linux::security::ResourceLimits {
        nofile: 1024,
        memlock_bytes: 64 * 1024 * 1024, // 64M
    });

    let (layout, config) = core_daemon::startup()?;

    // Probe memfd_secret and initialize secure memory BEFORE sandbox.
    core_types::init_secure_memory();

    // The sandbox is applied on the only thread; the runtime's threads
    // and the configuration watcher start inside it.
    #[cfg(target_os = "linux")]
    sandbox::apply_sandbox(&layout, &config)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start the async runtime")?
        .block_on(run(cli, layout, config))
}

/// The daemon, from bus connection to shutdown, inside the sandbox.
async fn run(
    cli: Cli,
    layout: core_layout::Layout,
    config: core_config::Config,
) -> anyhow::Result<()> {
    // Authorization requires both accepted observation and consumer adoption.
    let mut events = EventLoop::new(
        IDENTITY.daemon,
        Shutdown::register()?,
        core_daemon::watch_config(&layout, config)?,
    );
    let mut client = core_daemon::connect_bus(&layout, &IDENTITY).await?;
    events.candidate()?.applied(&client).await;
    tracing::info!("connected to IPC bus (Noise IK encrypted)");
    core_daemon::announce_started(&client, &IDENTITY).await;
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();
    tracing::info!("daemon-secrets ready (locked, awaiting FactorSubmit)");

    // Individual profiles are unlocked/locked independently.
    let mut vault_state = VaultState::new(layout, Duration::from_secs(cli.ttl));
    let mut rate_limiter = SecretRateLimiter::new();
    let mut partial_sweep = tokio::time::interval(PARTIAL_UNLOCK_SWEEP_INTERVAL);
    partial_sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let ended = loop {
        let wake = match events.next(&mut client, partial_sweep.tick()).await {
            Ok(wake) => wake,
            Err(e) => break Err(e),
        };
        match wake {
            Wake::Own(_) => vault_state.sweep_expired_partials(),
            Wake::Message(msg) => {
                let mut ctx = MessageContext {
                    client: &mut client,
                    vault_state: &mut vault_state,
                    rate_limiter: &mut rate_limiter,
                    config: events.application(),
                };
                dispatch::handle_message(&msg, &mut ctx).await;
            }
            Wake::ConfigReloaded(reloaded) => {
                // ACLs are acquired coherently at request admission. Vault
                // keying comes from each vault's metadata, not these layers.
                reloaded.applied(&client).await;
            }
            Wake::Shutdown(_) => break Ok(()),
        }
    };

    // Every exit, a lost bus included: every vault flushed and closed (its
    // SQLCipher key buffer scrubbed), every master key zeroized.
    vault_state.lock_all().await;
    ended?;

    core_daemon::announce_stopped(&client).await;

    tracing::info!("daemon-secrets shut down");
    Ok(())
}

/// Fixtures shared by the crate's tests.
#[cfg(test)]
mod test_support {
    use crate::vault::{MasterKey, VaultState};
    use core_crypto::SecureBytes;
    use core_types::{HkdfAlgorithm, TrustProfileName};
    use std::path::Path;
    use std::time::Duration;

    /// The profile named `name`.
    pub(crate) fn profile(name: &str) -> TrustProfileName {
        TrustProfileName::try_from(name).unwrap()
    }

    /// A master key whose bytes are `key`, deriving under BLAKE3.
    pub(crate) fn master_key(key: Vec<u8>) -> MasterKey {
        MasterKey {
            key: SecureBytes::new(key),
            hkdf: HkdfAlgorithm::Blake3,
        }
    }

    /// A deterministic test master key.
    pub(crate) fn test_master_key() -> MasterKey {
        master_key(
            (0..32u8)
                .map(|i| i.wrapping_mul(13).wrapping_add(7))
                .collect(),
        )
    }

    /// A `VaultState` under `root` with no vault unlocked.
    pub(crate) fn empty_vault_state(root: &Path) -> VaultState {
        VaultState::new(core_layout::Layout::under(root), Duration::from_mins(1))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{empty_vault_state, master_key, profile, test_master_key};
    use crate::vault::{MasterKey, VaultState};

    use core_crypto::SecureBytes;
    use core_secrets::SecretsStore;
    use core_types::{AuthFactorId, HkdfAlgorithm, TrustProfileName};
    use std::collections::HashSet;
    use std::path::Path;

    /// A `VaultState` with the test profiles unlocked under the test key.
    fn make_vault_state(root: &Path) -> VaultState {
        let mut state = empty_vault_state(root);
        for name in ["work", "alpha", "beta", "never-activated"] {
            state.master_keys.insert(profile(name), test_master_key());
        }
        state
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

    #[tokio::test]
    async fn locking_every_vault_clears_authorization_keys_and_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = make_vault_state(dir.path());
        for name in ["alpha", "beta"] {
            state.activate_profile(&profile(name));
            state.vault_for(&profile(name)).await.unwrap();
        }
        let mut locked = state.lock_all().await;
        locked.sort();
        assert_eq!(
            locked,
            ["alpha", "beta", "never-activated", "work"].map(profile)
        );
        assert!(state.active_profiles().is_empty());
        assert!(state.master_keys.is_empty());
        assert!(state.vaults.is_empty());
        for name in ["alpha", "beta"] {
            assert!(state.vault_for(&profile(name)).await.is_err());
        }
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
        let mut state = empty_vault_state(dir.path());
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

        state.lock(&a).await;
        assert!(!state.master_keys.contains_key(&a));
        assert!(!state.vaults.contains_key(&a));
        assert!(
            state.vault_for(&a).await.is_err(),
            "locked profile should fail"
        );
        assert!(
            state.vault_for(&b).await.is_ok(),
            "other profile should still work"
        );
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

        let mut state = empty_vault_state(dir.path());
        let pa = profile("alpha");
        let pb = profile("beta");
        state.master_keys.insert(pa.clone(), master_key(key_a));
        state.master_keys.insert(pb.clone(), master_key(key_b));
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

    #[tokio::test]
    async fn vaults_open_only_under_their_own_derivation() {
        let dir = tempfile::tempdir().unwrap();
        let (path, p) = (dir.path().join("work.db"), profile("work"));
        let under = |hkdf| MasterKey {
            key: SecureBytes::new(vec![9; 32]),
            hkdf,
        };
        crate::vault::open_vault(path.clone(), &under(HkdfAlgorithm::HkdfSha256), &p)
            .await
            .unwrap();
        assert!(
            crate::vault::open_vault(path.clone(), &under(HkdfAlgorithm::Blake3), &p)
                .await
                .is_err()
        );
        assert!(
            crate::vault::open_vault(path, &under(HkdfAlgorithm::HkdfSha256), &p)
                .await
                .is_ok()
        );
    }

    // -- D. Vault auth query --

    #[test]
    fn vault_auth_query_reports_unreadable_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_vault_state(dir.path());
        match crate::unlock::vault_auth_requirements(&state, &profile("work")) {
            core_types::EventKind::VaultAuthQueryResponse {
                error: Some(error),
                enrolled_factors,
                ..
            } => {
                assert!(error.contains("work.vault-meta"), "{error}");
                assert!(enrolled_factors.is_empty());
            }
            other => panic!("expected an error response, got {other:?}"),
        }
    }

    #[test]
    fn vault_auth_query_reports_enrolled_factors() {
        let dir = tempfile::tempdir().unwrap();
        let state = make_vault_state(dir.path());
        let p = profile("work");
        core_auth::VaultMetadata::new(
            vec![(AuthFactorId::Password, "master password".into())],
            core_types::AuthCombineMode::Any,
            &core_types::CryptoConfig::default(),
        )
        .unwrap()
        .save(&state.layout, &p)
        .unwrap();
        match crate::unlock::vault_auth_requirements(&state, &p) {
            core_types::EventKind::VaultAuthQueryResponse {
                error: None,
                enrolled_factors,
                partial_in_progress: false,
                ..
            } => assert_eq!(enrolled_factors, [AuthFactorId::Password]),
            other => panic!("expected the enrolled factors, got {other:?}"),
        }
    }
}
