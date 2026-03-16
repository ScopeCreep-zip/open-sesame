//! daemon-launcher: Application launcher daemon.
//!
//! Scans XDG desktop entries, builds a nucleo fuzzy index with frecency
//! ranking, and serves LaunchQuery/LaunchExecute requests over the IPC bus.
//!
//! GTK4 layer-shell UI is behind the `gtk` feature flag.

use anyhow::Context;
use clap::Parser;
use core_fuzzy::{FrecencyDb, FuzzyMatcher, SearchEngine, inject_items};
use core_ipc::{BusClient, Message};
use core_types::{
    DaemonId, EventKind, LaunchDenial, LaunchResult, SecurityLevel, TrustProfileName,
};
use std::collections::HashMap;
use std::sync::Arc;

mod scanner;

#[derive(Parser)]
#[command(name = "daemon-launcher")]
struct Cli {
    /// Profile to scope the launcher to.
    #[arg(long, default_value = "default")]
    profile: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Validate profile name at CLI boundary (fail-fast).
    let profile: TrustProfileName = TrustProfileName::try_from(cli.profile.clone())
        .map_err(|e| anyhow::anyhow!("invalid trust profile name '{}': {e}", cli.profile))?;

    // Logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing::info!("daemon-launcher starting");

    // -- Process hardening --
    #[cfg(target_os = "linux")]
    platform_linux::security::harden_process();

    // Config hot-reload.
    let config = core_config::load_config(None).context("failed to load config")?;
    let config_paths = core_config::resolve_config_paths(None);
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let (_config_watcher, _config_state) = core_config::ConfigWatcher::with_callback(
        &config_paths,
        config,
        Some(Box::new(move || {
            let _ = reload_tx.blocking_send(());
        })),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Frecency DB: per-profile, plaintext SQLite (not secrets).
    let data_dir = core_config::config_dir().join("launcher");
    std::fs::create_dir_all(&data_dir).context("failed to create launcher data directory")?;
    let frecency_path = data_dir.join(format!("{}.frecency.db", &*profile));
    let frecency = FrecencyDb::open(&frecency_path).context("failed to open frecency database")?;

    // Fuzzy matcher.
    let matcher = FuzzyMatcher::new(Arc::new(|| {}));

    // Scan desktop entries (blocking I/O) — cache Exec lines before sandbox.
    let (items, entry_cache) = tokio::task::spawn_blocking(|| {
        let items = scanner::scan();
        let cached = scanner::scan_cached();
        let cache: HashMap<String, scanner::CachedEntry> =
            cached.into_iter().map(|e| (e.id.clone(), e)).collect();
        (items, cache)
    })
    .await
    .context("desktop entry scan task failed")?;
    let item_count = items.len();

    // Inject items into the matcher.
    let injector = matcher.injector();
    inject_items(&injector, items);
    tracing::info!(item_count, "desktop entries indexed");

    // Search engine: fuzzy + frecency.
    let mut engine = SearchEngine::new(matcher, frecency, profile.clone());
    engine.refresh_frecency().ok(); // Non-fatal if DB is empty.

    // Connect to IPC bus: read keypair BEFORE sandbox.
    let socket_path = core_ipc::socket_path().context("failed to resolve IPC socket path")?;
    let server_pub = core_ipc::noise::read_bus_public_key()
        .await
        .context("daemon-profile is not running (no bus public key found)")?;
    let daemon_id = DaemonId::new();
    let msg_ctx = core_ipc::MessageContext::new(daemon_id);

    // Connect with keypair retry (daemon-profile may regenerate on crash-restart).
    let (mut client, _client_keypair) = BusClient::connect_with_keypair_retry(
        "daemon-launcher",
        daemon_id,
        &socket_path,
        &server_pub,
        5,
        std::time::Duration::from_millis(500),
    )
    .await
    .context("failed to connect to IPC bus")?;
    // ZeroizingKeypair: private key zeroized on drop (no manual zeroize needed).
    drop(_client_keypair);

    // Sandbox (Linux) — seccomp only; no Landlock because child processes inherit
    // Landlock rules, which would break arbitrary application launches.
    #[cfg(target_os = "linux")]
    apply_sandbox();

    // Announce startup.
    client
        .publish(
            EventKind::DaemonStarted {
                daemon_id,
                version: env!("CARGO_PKG_VERSION").into(),
                capabilities: vec!["launcher".into(), "fuzzy-search".into()],
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    // Platform readiness.
    #[cfg(target_os = "linux")]
    platform_linux::systemd::notify_ready();

    tracing::info!("daemon-launcher ready, entering event loop");

    // Watchdog timer: half the WatchdogSec=30 interval.
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(15));

    // Event loop.
    let mut watchdog_count: u64 = 0;
    loop {
        tokio::select! {
            _ = watchdog.tick() => {
                watchdog_count += 1;
                if watchdog_count <= 3 || watchdog_count % 20 == 0 {
                    tracing::info!(watchdog_count, "watchdog tick");
                }
                #[cfg(target_os = "linux")]
                platform_linux::systemd::notify_watchdog();
            }
            Some(msg) = client.recv() => {
                // Skip self-published messages to prevent feedback loops.
                if msg.sender == daemon_id {
                    continue;
                }

                let response_event = match &msg.payload {
                    EventKind::LaunchQuery { query, max_results, profile } => {
                        // Switch frecency context if profile differs.
                        if let Some(p) = profile
                            && p != engine.profile_id()
                            && let Err(e) = engine.switch_profile(p.clone())
                        {
                            tracing::warn!(profile = %p, error = %e, "frecency profile switch failed");
                        }
                        let results = engine.query(query, *max_results);
                        Some(EventKind::LaunchQueryResponse {
                            results: results
                                .into_iter()
                                .map(|r| LaunchResult {
                                    entry_id: r.entry_id,
                                    name: r.name,
                                    icon: r.icon,
                                    score: r.score,
                                })
                                .collect(),
                        })
                    }

                    EventKind::LaunchExecute { entry_id, profile, tags, launch_args } => {
                        // Record the launch for frecency.
                        if let Err(e) = engine.record_launch(entry_id) {
                            tracing::warn!(entry_id, error = %e, "frecency record failed");
                        }

                        // Look up the Exec line from the pre-sandbox cache.
                        match launch_entry(entry_id, profile.as_ref().map(|p| p.as_ref()), tags, launch_args, &entry_cache, &client, &_config_state).await {
                            Ok(pid) => Some(EventKind::LaunchExecuteResponse { pid, error: None, denial: None }),
                            Err(LaunchError::Denial(denial)) => {
                                let error_msg = format!("{denial:?}");
                                tracing::error!(entry_id, ?denial, "launch denied");
                                Some(EventKind::LaunchExecuteResponse { pid: 0, error: Some(error_msg), denial: Some(denial) })
                            }
                            Err(LaunchError::Other(e)) => {
                                tracing::error!(entry_id, error = %e, "launch failed");
                                Some(EventKind::LaunchExecuteResponse {
                                    pid: 0,
                                    error: Some(e.to_string()),
                                    denial: Some(LaunchDenial::SpawnFailed { reason: e.to_string() }),
                                })
                            }
                        }
                    }

                    // Key rotation — reconnect with new keypair.
                    EventKind::KeyRotationPending { daemon_name, new_pubkey, grace_period_s }
                        if daemon_name == "daemon-launcher" =>
                    {
                        tracing::info!(grace_period_s, "key rotation pending, will reconnect with new keypair");
                        match BusClient::handle_key_rotation(
                            "daemon-launcher", daemon_id, &socket_path, &server_pub, new_pubkey,
                            vec!["launcher".into(), "fuzzy-search".into()], env!("CARGO_PKG_VERSION"),
                        ).await {
                            Ok(new_client) => {
                                client = new_client;
                                tracing::info!("reconnected with rotated keypair");
                            }
                            Err(e) => tracing::error!(error = %e, "key rotation reconnect failed"),
                        }
                        None
                    }

                    // Ignore events not addressed to us.
                    _ => None,
                };

                if let Some(event) = response_event {
                    let response = Message::new(
                        &msg_ctx,
                        event,
                        msg.security_level,
                        client.epoch(),
                    )
                    .with_correlation(msg.msg_id);
                    if let Err(e) = client.send(&response).await {
                        tracing::warn!(error = %e, "failed to send response");
                    }
                }
            }
            Some(()) = reload_rx.recv() => {
                tracing::info!("config reloaded");
                client.publish(
                    EventKind::ConfigReloaded {
                        daemon_id,
                        changed_keys: vec!["launcher".into()],
                    },
                    SecurityLevel::Internal,
                ).await.ok();
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("SIGINT received, shutting down");
                break;
            }
            _ = sigterm() => {
                tracing::info!("SIGTERM received, shutting down");
                break;
            }
        }
    }

    // Best-effort shutdown announcement.
    client
        .publish(
            EventKind::DaemonStopped {
                daemon_id,
                reason: "shutdown".into(),
            },
            SecurityLevel::Internal,
        )
        .await
        .ok();

    tracing::info!("daemon-launcher shutting down");
    Ok(())
}

/// Wait for SIGTERM (Unix) or block forever on non-Unix.
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

/// Apply seccomp sandbox (Linux only).
///
/// daemon-launcher uses seccomp ONLY (no Landlock) because Landlock rules inherit
/// to child processes. Since daemon-launcher spawns arbitrary applications via
/// `LaunchExecute`, Landlock inheritance would restrict those applications to the
/// launcher's filesystem view, breaking them. seccomp is acceptable because
/// daemon-launcher has `Internal` clearance (not `SecretsOnly`) and does not
/// handle raw secret values.
#[cfg(target_os = "linux")]
fn apply_sandbox() {
    use platform_linux::sandbox::{SeccompProfile, apply_seccomp};

    let seccomp = SeccompProfile {
        daemon_name: "daemon-launcher".into(),
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
            "fcntl".into(),
            "flock".into(),
            "mkdir".into(),
            "getdents64".into(),
            "fdatasync".into(),
            "ioctl".into(),
            // Memory
            "mmap".into(),
            "mprotect".into(),
            "munmap".into(),
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
            "sendmsg".into(),
            "recvmsg".into(),
            "shutdown".into(),
            "getsockopt".into(),
            "socketpair".into(),
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
            // Process spawning (LaunchExecute needs fork/exec).
            "execve".into(),
            "execveat".into(),
            "wait4".into(),
            "vfork".into(),
        ],
    };

    // Seccomp only — no Landlock because child processes inherit Landlock rules.
    match apply_seccomp(&seccomp) {
        Ok(()) => {
            tracing::info!("sandbox applied (seccomp only, no Landlock)");
        }
        Err(e) => {
            panic!("sandbox application failed: {e} — refusing to run unsandboxed");
        }
    }
}

/// Resolve a desktop entry ID against the cache with fallback strategies.
///
/// 1. Exact match on the full ID
/// 2. Last dot-separated segment match (e.g. "firefox" matches "org.mozilla.firefox")
/// 3. Case-insensitive full ID match
fn resolve_entry<'a>(
    entry_id: &str,
    cache: &'a HashMap<String, scanner::CachedEntry>,
) -> Option<&'a scanner::CachedEntry> {
    // Strategy 1: exact match
    if let Some(entry) = cache.get(entry_id) {
        return Some(entry);
    }

    // Strategy 2: last segment match (e.g., "firefox" matches "org.mozilla.firefox")
    let lower = entry_id.to_lowercase();
    if let Some(entry) = cache.values().find(|e| {
        e.id.rsplit('.')
            .next()
            .map(|seg| seg.to_lowercase() == lower)
            .unwrap_or(false)
    }) {
        tracing::info!(entry_id, resolved_id = %entry.id, "resolved via last-segment match");
        return Some(entry);
    }

    // Strategy 3: case-insensitive full ID match
    if let Some(entry) = cache.values().find(|e| e.id.to_lowercase() == lower) {
        tracing::info!(entry_id, resolved_id = %entry.id, "resolved via case-insensitive match");
        return Some(entry);
    }

    None
}

/// Launch a desktop entry by its app ID using the pre-sandbox cache.
///
/// Looks up the entry's Exec line from the cache (populated before sandbox),
/// strips field codes, and spawns the process.
/// If `profile` is provided, `SESAME_PROFILE` is injected into the child environment
/// so the launched application (or sesame SDK) can request profile-scoped secrets.
/// Structured launch error — carries machine-readable denial for the WM.
enum LaunchError {
    /// A structured denial the WM can act on (e.g. prompt for vault unlock).
    Denial(LaunchDenial),
    /// An unstructured error (spawn failure, IPC error, etc.).
    Other(anyhow::Error),
}

impl From<anyhow::Error> for LaunchError {
    fn from(e: anyhow::Error) -> Self {
        LaunchError::Other(e)
    }
}

///
/// Launch profile `tags` are resolved to compose environment variables, secrets,
/// and optional devshell wrapping. Tags support qualified cross-profile references
/// (`"work:corp"` resolves `corp` in the `work` trust profile).
async fn launch_entry(
    entry_id: &str,
    profile: Option<&str>,
    tags: &[String],
    launch_args: &[String],
    cache: &HashMap<String, scanner::CachedEntry>,
    client: &BusClient,
    config_state: &Arc<std::sync::RwLock<core_config::Config>>,
) -> Result<u32, LaunchError> {
    let cached =
        resolve_entry(entry_id, cache).ok_or(LaunchError::Denial(LaunchDenial::EntryNotFound))?;

    let exec = scanner::strip_field_codes(&cached.exec);
    let parts = scanner::tokenize_exec(&exec);
    if parts.is_empty() {
        return Err(LaunchError::Other(anyhow::anyhow!(
            "empty Exec line for '{entry_id}'"
        )));
    }

    // Resolve launch profiles from config (passed from hot-reload watcher)
    let default_profile = profile.unwrap_or("default");
    let config = config_state
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let mut composed_env: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut all_secrets: Vec<(String, String)> = Vec::new(); // (secret_name, trust_profile_name)
    let mut devshell: Option<String> = None;
    let mut cwd: Option<String> = None;

    if !tags.is_empty() {
        for tag in tags {
            let (tp_name, lp_name) = parse_tag(tag, default_profile);

            let tp = config.profiles.get(&tp_name).ok_or_else(|| {
                LaunchError::Denial(LaunchDenial::ProfileNotFound {
                    profile: tp_name.clone(),
                })
            })?;

            let lp = tp.launch_profiles.get(&lp_name).ok_or_else(|| {
                LaunchError::Denial(LaunchDenial::LaunchProfileNotFound {
                    profile: tp_name.clone(),
                    launch_profile: lp_name.clone(),
                })
            })?;

            // Merge env (later tag wins on conflict)
            for (k, v) in &lp.env {
                composed_env.insert(k.clone(), v.clone());
            }

            // Last devshell wins
            if lp.devshell.is_some() {
                devshell.clone_from(&lp.devshell);
            }

            // Last cwd wins
            if lp.cwd.is_some() {
                cwd.clone_from(&lp.cwd);
            }

            // Collect secrets with their owning trust profile
            for secret in &lp.secrets {
                if !all_secrets.iter().any(|(s, _)| s == secret) {
                    all_secrets.push((secret.clone(), tp_name.clone()));
                }
            }
        }
    }

    // Fetch secrets via IPC — collect ALL denials before aborting so the WM
    // can prompt for all required vault unlocks at once.
    let mut locked_profiles: Vec<TrustProfileName> = Vec::new();
    let mut missing_count: u32 = 0;

    for (secret_name, tp_name) in &all_secrets {
        let tp = core_types::TrustProfileName::try_from(tp_name.as_str())
            .map_err(|e| LaunchError::Other(anyhow::anyhow!("invalid trust profile name: {e}")))?;

        let response = client
            .request(
                EventKind::SecretGet {
                    profile: tp.clone(),
                    key: secret_name.clone(),
                },
                SecurityLevel::Internal,
                std::time::Duration::from_secs(5),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "secret fetch IPC failed");
                LaunchError::Other(anyhow::anyhow!("secret fetch IPC failed"))
            })?;

        match response.payload {
            EventKind::SecretGetResponse {
                key: _,
                value,
                denial,
            } => {
                if let Some(reason) = denial {
                    tracing::error!(secret = %secret_name, ?reason, "secret fetch denied");
                    match reason {
                        core_types::SecretDenialReason::ProfileNotActive
                        | core_types::SecretDenialReason::Locked => {
                            if !locked_profiles.contains(&tp) {
                                locked_profiles.push(tp);
                            }
                        }
                        core_types::SecretDenialReason::NotFound => {
                            missing_count += 1;
                        }
                        core_types::SecretDenialReason::RateLimited => {
                            return Err(LaunchError::Denial(LaunchDenial::RateLimited));
                        }
                        _ => {
                            return Err(LaunchError::Other(anyhow::anyhow!(
                                "secret access denied: {reason:?}"
                            )));
                        }
                    }
                } else {
                    let env_var = secret_name_to_env_var(secret_name);
                    let secret_str = String::from_utf8(value.as_bytes().to_vec())
                        .context("secret value is not valid UTF-8")?;
                    composed_env.insert(env_var, secret_str);
                }
            }
            other => {
                tracing::error!(?other, "unexpected response to SecretGet");
                return Err(LaunchError::Other(anyhow::anyhow!(
                    "unexpected response to SecretGet"
                )));
            }
        }
    }

    // Check collected denials — locked vaults take priority over missing secrets
    if !locked_profiles.is_empty() {
        return Err(LaunchError::Denial(LaunchDenial::VaultsLocked {
            locked_profiles,
        }));
    }
    if missing_count > 0 {
        return Err(LaunchError::Denial(LaunchDenial::SecretNotFound {
            missing_count,
        }));
    }

    // Build command — wrap in devshell if configured
    let (program, args) = if let Some(ref ds) = devshell {
        let mut nix_args = vec!["develop".to_string(), ds.clone(), "-c".to_string()];
        nix_args.extend(parts.iter().cloned());
        ("nix".to_string(), nix_args)
    } else {
        (parts[0].clone(), parts[1..].to_vec())
    };

    let mut cmd = std::process::Command::new(&program);
    cmd.args(&args);

    // Append launch_args from the IPC message (e.g., workspace-specific flags).
    if !launch_args.is_empty() {
        cmd.args(launch_args);
    }

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // Set working directory if configured via launch profile cwd.
    if let Some(ref dir) = cwd {
        let path = std::path::Path::new(dir);
        if !path.is_absolute() {
            return Err(LaunchError::Other(anyhow::anyhow!(
                "cwd must be an absolute path, got: {dir}"
            )));
        }
        if !path.is_dir() {
            return Err(LaunchError::Other(anyhow::anyhow!(
                "cwd does not exist or is not a directory: {dir}"
            )));
        }
        cmd.current_dir(path);
    }

    // Inject composed env vars from launch profiles
    for (k, v) in &composed_env {
        cmd.env(k, v);
    }

    // Inject default SESAME_ vars (after composed env, cannot be overridden)
    cmd.env("SESAME_PROFILE", default_profile);
    cmd.env("SESAME_APP_ID", &cached.id);
    if let Ok(sock) = core_ipc::socket_path() {
        cmd.env("SESAME_SOCKET", sock.to_string_lossy().as_ref());
    }

    let child = cmd.spawn().context("failed to spawn process")?;

    tracing::info!(
        entry_id,
        pid = child.id(),
        ?tags,
        ?devshell,
        env_count = composed_env.len(),
        secret_count = all_secrets.len(),
        "launched with profiles"
    );

    Ok(child.id())
}

/// Parse a tag into (profile_name, launch_profile_name).
/// Unqualified: `"dev-rust"` → (default_profile, "dev-rust").
/// Qualified: `"work:corp"` → ("work", "corp").
fn parse_tag<'a>(tag: &'a str, default_profile: &'a str) -> (String, String) {
    match tag.split_once(':') {
        Some((profile, name)) => (profile.to_string(), name.to_string()),
        None => (default_profile.to_string(), tag.to_string()),
    }
}

/// Transform a secret name to an environment variable name.
/// Uppercase, hyphens to underscores.
fn secret_name_to_env_var(name: &str) -> String {
    name.to_uppercase().replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cache() -> HashMap<String, scanner::CachedEntry> {
        let entries = vec![
            scanner::CachedEntry {
                id: "org.mozilla.firefox".into(),
                exec: "firefox".into(),
            },
            scanner::CachedEntry {
                id: "com.mitchellh.ghostty".into(),
                exec: "ghostty".into(),
            },
            scanner::CachedEntry {
                id: "Alacritty".into(),
                exec: "alacritty".into(),
            },
        ];
        entries.into_iter().map(|e| (e.id.clone(), e)).collect()
    }

    #[test]
    fn resolve_exact_match() {
        let cache = test_cache();
        let entry = resolve_entry("org.mozilla.firefox", &cache).unwrap();
        assert_eq!(entry.id, "org.mozilla.firefox");
    }

    #[test]
    fn resolve_last_segment_match() {
        let cache = test_cache();
        let entry = resolve_entry("firefox", &cache).unwrap();
        assert_eq!(entry.id, "org.mozilla.firefox");
    }

    #[test]
    fn resolve_case_insensitive_match() {
        let cache = test_cache();
        let entry = resolve_entry("alacritty", &cache).unwrap();
        assert_eq!(entry.id, "Alacritty");
    }

    #[test]
    fn resolve_no_match() {
        let cache = test_cache();
        assert!(resolve_entry("nonexistent", &cache).is_none());
    }

    #[test]
    fn secret_name_to_env_var_basic() {
        assert_eq!(secret_name_to_env_var("github-token"), "GITHUB_TOKEN");
        assert_eq!(
            secret_name_to_env_var("anthropic-api-key"),
            "ANTHROPIC_API_KEY"
        );
        assert_eq!(secret_name_to_env_var("simple"), "SIMPLE");
        assert_eq!(secret_name_to_env_var("a-b-c"), "A_B_C");
    }

    #[test]
    fn parse_tag_unqualified() {
        let (profile, name) = parse_tag("dev-rust", "default");
        assert_eq!(profile, "default");
        assert_eq!(name, "dev-rust");
    }

    #[test]
    fn parse_tag_qualified() {
        let (profile, name) = parse_tag("work:corp", "default");
        assert_eq!(profile, "work");
        assert_eq!(name, "corp");
    }
}
